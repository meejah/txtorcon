from __future__ import with_statement

import os
import sys
import string
import types
import functools
import random
import tempfile
from StringIO import StringIO
import shlex
if sys.platform in ('linux2', 'darwin'):
    import pwd

from twisted.python import log
from twisted.internet import defer, error, protocol
from twisted.internet.interfaces import IStreamServerEndpoint, IReactorTime
from twisted.internet.endpoints import TCP4ClientEndpoint, TCP4ServerEndpoint
from twisted.internet.endpoints import clientFromString
from zope.interface import implements
from zope.interface import implementer
from zope.interface import Interface, Attribute
from twisted.internet.interfaces import IProtocolFactory, IListeningPort, IAddress
from twisted.python.util import FancyEqMixin
from twisted.plugin import IPlugin
from twisted.internet.interfaces import IStreamServerEndpointStringParser
from twisted.internet.endpoints import serverFromString
from twisted.python.usage import UsageError

import txtorcon
from txtorcon.torcontrolprotocol import parse_keywords, TorProtocolFactory
from txtorcon.util import delete_file_or_tree, find_keywords, find_tor_binary
from txtorcon.log import txtorlog
from txtorcon.interface import ITorControlProtocol


class TorNotFound(RuntimeError):
    """
    Raised by launch_tor() in case the tor binary was unspecified and could
    not be found by consulting the shell.
    """


class TorProcessProtocol(protocol.ProcessProtocol):

    def __init__(self, connection_creator, progress_updates=None, config=None,
                 ireactortime=None, timeout=None, kill_on_stderr=True,
                 stdout=None, stderr=None):
        """
        This will read the output from a Tor process and attempt a
        connection to its control port when it sees any 'Bootstrapped'
        message on stdout. You probably don't need to use this
        directly except as the return value from the
        :func:`txtorcon.launch_tor` method. tor_protocol contains a
        valid :class:`txtorcon.TorControlProtocol` instance by that
        point.

        connection_creator is a callable that should return a Deferred
        that callbacks with a :class:`txtorcon.TorControlProtocol`;
        see :func:`txtorcon.launch_tor` for the default one which is a
        functools.partial that will call
        ``connect(TorProtocolFactory())`` on an appropriate
        :api:`twisted.internet.endpoints.TCP4ClientEndpoint`

        :param connection_creator: A no-parameter callable which
            returns a Deferred which promises a :api:`twisted.internet.interfaces.IStreamClientEndpoint <IStreamClientEndpoint>`

        :param progress_updates: A callback which received progress
            updates with three args: percent, tag, summary

        :param config: a TorConfig object to connect to the
            TorControlProtocl from the launched tor (should it succeed)

        :param ireactortime:
            An object implementing IReactorTime (i.e. a reactor) which
            needs to be supplied if you pass a timeout.

        :param timeout:
            An int representing the timeout in seconds. If we are
            unable to reach 100% by this time we will consider the
            setting up of Tor to have failed. Must supply ireactortime
            if you supply this.

        :param kill_on_stderr:
            When True, kill subprocess if we receive anything on stderr

        :param stdout:
            Anything subprocess writes to stdout is sent to .write() on this

        :param stderr:
            Anything subprocess writes to stderr is sent to .write() on this

        :ivar tor_protocol: The TorControlProtocol instance connected
            to the Tor this :api:`twisted.internet.protocol.ProcessProtocol <ProcessProtocol>`` is speaking to. Will be valid
            when the `connected_cb` callback runs.

        :ivar connected_cb: Triggered when the Tor process we
            represent is fully bootstrapped

        """

        self.config = config
        self.tor_protocol = None
        self.connection_creator = connection_creator
        self.progress_updates = progress_updates

        self.connected_cb = defer.Deferred()

        self.attempted_connect = False
        self.to_delete = []
        self.kill_on_stderr = kill_on_stderr
        self.stderr = stderr
        self.stdout = stdout
        self.collected_stdout = StringIO()

        self._setup_complete = False
        self._did_timeout = False
        self._timeout_delayed_call = None
        if timeout:
            if not ireactortime:
                raise RuntimeError('Must supply an IReactorTime object when supplying a timeout')
            ireactortime = IReactorTime(ireactortime)
            self._timeout_delayed_call = ireactortime.callLater(timeout, self.timeout_expired)

    def outReceived(self, data):
        """
        :api:`twisted.internet.protocol.ProcessProtocol <ProcessProtocol>` API
        """

        if self.stdout:
            self.stdout.write(data)

        ## minor hack: we can't try this in connectionMade because
        ## that's when the process first starts up so Tor hasn't
        ## opened any ports properly yet. So, we presume that after
        ## its first output we're good-to-go. If this fails, we'll
        ## reset and try again at the next output (see this class'
        ## tor_connection_failed)

        txtorlog.msg(data)
        if not self.attempted_connect and 'Bootstrap' in data:
            self.attempted_connect = True
            d = self.connection_creator()
            d.addCallback(self.tor_connected)
            d.addErrback(self.tor_connection_failed)

    def timeout_expired(self):
        """
        A timeout was supplied during setup, and the time has run out.
        """

        try:
            self.transport.signalProcess('TERM')
        except error.ProcessExitedAlready:
            self.transport.loseConnection()
        self._did_timeout = True

    def errReceived(self, data):
        """
        :api:`twisted.internet.protocol.ProcessProtocol <ProcessProtocol>` API
        """

        if self.stderr:
            self.stderr.write(data)

        if self.kill_on_stderr:
            self.transport.loseConnection()
            raise RuntimeError("Received stderr output from slave Tor process: " + data)

    def cleanup(self):
        """
        Clean up my temporary files.
        """

        [delete_file_or_tree(f) for f in self.to_delete]
        self.to_delete = []

    def processEnded(self, status):
        """
        :api:`twisted.internet.protocol.ProcessProtocol <ProcessProtocol>` API
        """

        self.cleanup()

        if isinstance(status.value, error.ProcessDone) and not self._did_timeout:
            return

        if status.value.exitCode is None:
            if self._did_timeout:
                err = RuntimeError("Timeout waiting for Tor launch..")
            else:
                err = RuntimeError("Tor was killed (%s)." % status.value.signal)
        else:
            err = RuntimeError("Tor exited with error-code %d" % status.value.exitCode)

        log.err(err)
        if self.connected_cb:
            self.connected_cb.errback(err)
            self.connected_cb = None

    def progress(self, percent, tag, summary):
        """
        Can be overridden or monkey-patched if you want to get
        progress updates yourself.
        """

        if self.progress_updates:
            self.progress_updates(percent, tag, summary)

    ## the below are all callbacks

    def tor_connection_failed(self, failure):
        ## FIXME more robust error-handling please, like a timeout so
        ## we don't just wait forever after 100% bootstrapped (that
        ## is, we're ignoring these errors, but shouldn't do so after
        ## we'll stop trying)
        self.attempted_connect = False

    def status_client(self, arg):
        args = shlex.split(arg)
        if args[1] != 'BOOTSTRAP':
            return

        kw = find_keywords(args)
        prog = int(kw['PROGRESS'])
        tag = kw['TAG']
        summary = kw['SUMMARY']
        self.progress(prog, tag, summary)

        if prog == 100:
            if self._timeout_delayed_call:
                self._timeout_delayed_call.cancel()
                self._timeout_delayed_call = None
            if self.connected_cb:
                self.connected_cb.callback(self)
                self.connected_cb = None

    def tor_connected(self, proto):
        txtorlog.msg("tor_connected %s" % proto)

        self.tor_protocol = proto
        if self.config is not None:
            self.config._update_proto(proto)
        self.tor_protocol.is_owned = self.transport.pid
        self.tor_protocol.post_bootstrap.addCallback(self.protocol_bootstrapped).addErrback(self.tor_connection_failed)

    def protocol_bootstrapped(self, proto):
        txtorlog.msg("Protocol is bootstrapped")

        self.tor_protocol.add_event_listener('STATUS_CLIENT', self.status_client)

        ## FIXME: should really listen for these to complete as well
        ## as bootstrap etc. For now, we'll be optimistic.
        self.tor_protocol.queue_command('TAKEOWNERSHIP')
        self.tor_protocol.queue_command('RESETCONF __OwningControllerProcess')


def launch_tor(config, reactor,
               tor_binary=None,
               progress_updates=None,
               connection_creator=None,
               timeout=None,
               kill_on_stderr=True,
               stdout=None, stderr=None):
    """launches a new Tor process with the given config.

    :param kill_on_stderr:
        When True (the default), if Tor prints anything on stderr we
        kill off the process, close the TorControlProtocol and raise
        an exception.

    :param config: an instance of :class:`txtorcon.TorConfig` with any
        configuration values you want. :meth:`txtorcon.TorConfig.save`
        should have been called already (anything unsaved won't make
        it into the torrc produced). If ControlPort isn't set, 9052 is
        used; if DataDirectory isn't set, tempdir is used to create
        one.

    :param reactor: a Twisted IReactorCore implementation (usually
        twisted.internet.reactor)

    :param tor_binary: path to the Tor binary to run. Tries to find the tor
        binary if unset.

    :param progress_updates: a callback which gets progress updates; gets as
         args: percent, tag, summary (FIXME make an interface for this).

    :param connection_creator: is mostly available to ease testing, so
        you probably don't want to supply this. If supplied, it is a
        callable that should return a Deferred that delivers an
        :api:`twisted.internet.interfaces.IProtocol <IProtocol>` or ConnectError.
        See :api:`twisted.internet.interfaces.IStreamClientEndpoint`.connect

    :param stdout: a file-like object to which we write anything that
        Tor prints on stdout (just needs to support write()).

    :param stderr: a file-like object to which we write anything that
        Tor prints on stderr (just needs .write()). Note that we kill Tor
        off by default if anything appears on stderr; pass "no_kill=True"
        if you don't like the behavior.

    :return: a Deferred which callbacks with a TorProcessProtocol
        connected to the fully-bootstrapped Tor; this has a
        :class:`txtorcon.TorControlProtocol` instance as `.tor_protocol`. In Tor,
        ``__OwningControllerProcess`` will be set and TAKEOWNERSHIP will have
        been called, so if you close the TorControlProtocol the Tor should
        exit also (see `control-spec <https://gitweb.torproject.org/torspec.git/blob/HEAD:/control-spec.txt>`_ 3.23).

    HACKS:

     1. It's hard to know when Tor has both (completely!) written its
        authentication cookie file AND is listening on the control
        port. It seems that waiting for the first 'bootstrap' message on
        stdout is sufficient. Seems fragile...and doesn't work 100% of
        the time, so FIXME look at Tor source.

    """

    ## We have a slight problem with the approach: we need to pass a
    ## few minimum values to a torrc file so that Tor will start up
    ## enough that we may connect to it. Ideally, we'd be able to
    ## start a Tor up which doesn't really do anything except provide
    ## "AUTHENTICATE" and "GETINFO config/names" so we can do our
    ## config validation.

    ## the other option here is to simply write a torrc version of our
    ## config and get Tor to load that...which might be the best
    ## option anyway.

    ## actually, can't we pass them all as command-line arguments?
    ## could be pushing some limits for giant configs...

    if tor_binary is None:
        tor_binary = find_tor_binary()
    if tor_binary is None:
        # We fail right here instead of waiting for the reactor to start
        raise TorNotFound('Tor binary could not be found')

    if config.needs_save():
        log.msg("Config was unsaved when launch_tor() called; calling save().")
        config.save()

    # make sure we got things that have write() for stderr, stdout
    # kwargs
    for arg in [stderr, stdout]:
        if arg and not getattr(arg, "write"):
            raise RuntimeError('File-like object needed for stdout or stderr args.')

    try:
        data_directory = config.DataDirectory
        user_set_data_directory = True
    except KeyError:
        user_set_data_directory = False
        data_directory = tempfile.mkdtemp(prefix='tortmp')
        config.DataDirectory = data_directory

        # Set ownership on the temp-dir to the user tor will drop privileges to
        # when executing as root.
        try:
            user = config.User
        except KeyError:
            pass
        else:
            if sys.platform in ('linux2', 'darwin') and os.geteuid() == 0:
                os.chown(data_directory, pwd.getpwnam(user).pw_uid, -1)

    try:
        control_port = config.ControlPort
    except KeyError:
        control_port = 9052
        config.ControlPort = control_port

    config.CookieAuthentication = 1
    config.__OwningControllerProcess = os.getpid()
    config.save()

    (fd, torrc) = tempfile.mkstemp(prefix='tortmp')
    os.write(fd, config.create_torrc())
    os.close(fd)

    # txtorlog.msg('Running with config:\n', open(torrc, 'r').read())

    if connection_creator is None:
        connection_creator = functools.partial(TCP4ClientEndpoint(reactor, 'localhost', control_port).connect,
                                               TorProtocolFactory())
    process_protocol = TorProcessProtocol(connection_creator, progress_updates,
                                          config, reactor, timeout,
                                          kill_on_stderr,
                                          stdout, stderr)

    # we set both to_delete and the shutdown events because this
    # process might be shut down way before the reactor, but if the
    # reactor bombs out without the subprocess getting closed cleanly,
    # we'll want the system shutdown events triggered so the temporary
    # files get cleaned up

    # we don't want to delete the user's directories, just our
    # temporary ones
    if user_set_data_directory:
        process_protocol.to_delete = [torrc]
        reactor.addSystemEventTrigger('before', 'shutdown',
                                      functools.partial(delete_file_or_tree,
                                                        torrc))
    else:
        process_protocol.to_delete = [torrc, data_directory]
        reactor.addSystemEventTrigger('before', 'shutdown',
                                      functools.partial(delete_file_or_tree,
                                                        torrc,
                                                        data_directory))

    try:
        log.msg('Spawning tor process with DataDirectory', data_directory)
        transport = reactor.spawnProcess(process_protocol, tor_binary,
                                         args=(tor_binary, '-f', torrc),
                                         env={'HOME': data_directory},
                                         path=data_directory)
        #FIXME? don't need rest of the args: uid, gid, usePTY, childFDs)
        transport.closeStdin()

    except RuntimeError, e:
        return defer.fail(e)

    if process_protocol.connected_cb:
        return process_protocol.connected_cb
    return defer.succeed(process_protocol)


class TorConfigType(object):
    """
    Base class for all configuration types, which function as parsers
    and un-parsers.
    """

    def parse(self, s):
        """
        Given the string s, this should return a parsed representation
        of it.
        """
        return s

    def validate(self, s, instance, name):
        """
        If s is not a valid type for this object, an exception should
        be thrown. The validated object should be returned.
        """
        return s


class Boolean(TorConfigType):
    def parse(self, s):
        if int(s):
            return True
        return False


class Boolean_Auto(TorConfigType):
    """
    weird class-name, but see the parser for these which is *mostly*
    just the classname <==> string from Tor, except for something
    called Boolean+Auto which is replace()d to be Boolean_Auto
    """

    def parse(self, s):
        if s == 'auto' or int(s) < 0:
            return -1
        if int(s):
            return 1
        return 0


class Integer(TorConfigType):
    def parse(self, s):
        return int(s)


class SignedInteger(Integer):
    pass


class Port(Integer):
    pass


class TimeInterval(Integer):
    pass


## not actually used?
class TimeMsecInterval(TorConfigType):
    pass


class DataSize(Integer):
    pass


class Float(TorConfigType):
    def parse(self, s):
        return float(s)


## unused also?
class Time(TorConfigType):
    pass


class CommaList(TorConfigType):
    def parse(self, s):
        return map(string.strip, s.split(','))


## FIXME: is this really a comma-list?
class RouterList(CommaList):
    pass


class String(TorConfigType):
    pass


class Filename(String):
    pass


class LineList(TorConfigType):
    def parse(self, s):
        if isinstance(s, types.ListType):
            return map(str, s)
        return map(string.strip, s.split('\n'))

    def validate(self, obj, instance, name):
        if not isinstance(obj, types.ListType):
            raise ValueError("Not valid for %s: %s" % (self.__class__, obj))
        return _ListWrapper(obj, functools.partial(instance.mark_unsaved, name))

config_types = [Boolean, Boolean_Auto, LineList, Integer, SignedInteger, Port,
                TimeInterval, TimeMsecInterval,
                DataSize, Float, Time, CommaList, String, LineList, Filename,
                RouterList]


def _wrapture(orig):
    """
    Returns a new method that wraps orig (the original method) with
    something that first calls on_modify from the
    instance. _ListWrapper uses this to wrap all methods that modify
    the list.
    """

#    @functools.wraps(orig)
    def foo(*args):
        obj = args[0]
        obj.on_modify()
        return orig(*args)
    return foo


class _ListWrapper(list):
    """
    Do some voodoo to wrap lists so that if you do anything to modify
    it, we mark the config as needing saving.

    FIXME: really worth it to preserve attribute-style access? seems
    to be okay from an exterior API perspective....
    """

    def __init__(self, thelist, on_modify_cb):
        list.__init__(self, thelist)
        self.on_modify = on_modify_cb

    __setitem__ = _wrapture(list.__setitem__)
    __setslice__ = _wrapture(list.__setslice__)
    append = _wrapture(list.append)
    extend = _wrapture(list.extend)
    insert = _wrapture(list.insert)
    remove = _wrapture(list.remove)
    pop = _wrapture(list.pop)

    def __repr__(self):
        return '_ListWrapper' + super(_ListWrapper, self).__repr__()


class HiddenService(object):
    """
    Because hidden service configuration is handled specially by Tor,
    we wrap the config in this class. This corresponds to the
    HiddenServiceDir, HiddenServicePort, HiddenServiceVersion and
    HiddenServiceAuthorizeClient lines from the config. If you want
    multiple HiddenServicePort lines, simply append more strings to
    the ports member.

    To create an additional hidden service, append a new instance of
    this class to the config (ignore the conf argument)::

    state.hiddenservices.append(HiddenService('/path/to/dir', ['80 127.0.0.1:1234']))
    """

    def __init__(self, config, thedir, ports, auth=None, ver=2):
        """
        config is the TorConfig to which this will belong (FIXME,
        can't we make this automatic somehow?), thedir corresponds to
        'HiddenServiceDir' and will ultimately contain a 'hostname'
        and 'private_key' file, ports is a list of lines corresponding
        to HiddenServicePort (like '80 127.0.0.1:1234' to advertise a
        hidden service at port 80 and redirect it internally on
        127.0.0.1:1234). auth corresponds to
        HiddenServiceAuthenticateClient line (FIXME: is that lines?)
        and ver corresponds to HiddenServiceVersion and is always 2
        right now.
        """

        self.conf = config
        self.dir = thedir
        self.version = ver
        self.authorize_client = auth

        ## there are two magic attributes, "hostname" and "private_key"
        ## these are gotten from the dir if they're still None when
        ## accessed. Note that after a SETCONF has returned '250 OK'
        ## it seems from tor code that the keys will always have been
        ## created on disk by that point

        if not isinstance(ports, types.ListType):
            ports = [ports]
        self.ports = _ListWrapper(ports, functools.partial(self.conf.mark_unsaved,
                                                           'HiddenServices'))

    def __setattr__(self, name, value):
        """
        We override the default behavior so that we can mark
        HiddenServices as unsaved in our TorConfig object if anything
        is changed.
        """

        if name in ['dir', 'version', 'authorize_client', 'ports'] and self.conf:
            self.conf.mark_unsaved('HiddenServices')
        if isinstance(value, types.ListType):
            value = _ListWrapper(value, functools.partial(self.conf.mark_unsaved,
                                                          'HiddenServices'))
        self.__dict__[name] = value

    def __getattr__(self, name):
        if name in ('hostname', 'private_key'):
            with open(os.path.join(self.dir, name)) as f:
                self.__dict__[name] = f.read().strip()
        return self.__dict__[name]

    def config_attributes(self):
        """
        Helper method used by TorConfig when generating a torrc file.
        """

        rtn = [('HiddenServiceDir', self.dir)]
        for x in self.ports:
            rtn.append(('HiddenServicePort', x))
        if self.version:
            rtn.append(('HiddenServiceVersion', self.version))
        if self.authorize_client:
            rtn.append(('HiddenServiceAuthorizeClient', self.authorize_client))
        return rtn


class TorConfig(object):
    """
    This class abstracts out Tor's config so that you don't have to
    realize things like: in order to successfully set multiple listen
    addresses, you must put them all (and the or-ports) in one SETCONF
    call.

    Also, it gives easy access to all the configuration options
    present. This is loaded at "bootstrap" time (when all values are
    loaded) providing attribute-based access thereafter. If you set an
    item AND we're bootstrapped to a Tor, THEN that valud is NOT
    reflected in Tor until you do save() -- and neither is it
    reflected in the TorConfig instance until that time. So, you might
    get slightly confusing behavior like: ``config.SOCKSPort=1234;
    print config.SOCKSPort`` which will still print 9050 or whatever
    the original value is. (TODO is this really a good idea?
    Especially since we "need" the other behavior for "build config
    from scratch" use-case)

    You may also use this class to construct a configuration from
    scratch (e.g. to give to :func:`txtorcon.launch_tor`). In this
    case, values are reflected right away. (If we're not bootstrapped
    to a Tor, this is the mode).

    Note that you do not need to call save() if you're just using
    TorConfig to create a .torrc file or for input to launch_tor().

    This listens for CONF_CHANGED events to update the cached data in
    the event other controllers (etc) changed it.

    FIXME: when is CONF_CHANGED introduced in Tor? Can we do anything
    like it for prior versions?

    FIXME:

        - HiddenServiceOptions is special: GETCONF on it returns
        several (well, two) values. Besides adding the two keys 'by
        hand' do we need to do anything special? Can't we just depend
        on users doing 'conf.hiddenservicedir = foo' AND
        'conf.hiddenserviceport = bar' before a save() ?

        - once I determine a value is default, is there any way to
          actually get what this value is?
    """

    def __init__(self, control=None):
        self.config = {}
        '''Current configuration, by keys.'''

        if control is None:
            self._protocol = None
            self.__dict__['_slutty_'] = None
            self.__dict__['config']['HiddenServices'] = _ListWrapper([], functools.partial(self.mark_unsaved, 'HiddenServices'))

        else:
            self._protocol = ITorControlProtocol(control)

        self.unsaved = {}
        '''Configuration that has been changed since last save().'''

        self.parsers = {}
        '''Instances of the parser classes, subclasses of TorConfigType'''

        self.post_bootstrap = defer.Deferred()
        if self.protocol:
            if self.protocol.post_bootstrap:
                self.protocol.post_bootstrap.addCallback(self.bootstrap).addErrback(log.err)
            else:
                self.bootstrap()

        else:
            self.post_bootstrap.callback(self)

        self.__dict__['_setup_'] = None

    """
    read-only access to TorControlProtocol. Call attach_protocol() to
    set it, which can only be done if we don't already have a
    protocol.
    """
    def _get_protocol(self):
        return self.__dict__['_protocol']
    protocol = property(_get_protocol)

    def attach_protocol(self, proto):
        """
        returns a Deferred that fires once we've set this object up to
        track the protocol. Fails if we already have a protocol.
        """
        if self._protocol is not None:
            raise RuntimeError("Already have a protocol.")
        # make sure we have nothing in self.unsaved
        self.save()
        self.__dict__['_protocol'] = proto

        # FIXME some of this is duplicated from ctor
        del self.__dict__['_slutty_']
        self.__dict__['post_bootstrap'] = defer.Deferred()
        if proto.post_bootstrap:
            proto.post_bootstrap.addCallback(self.bootstrap)
        else:
            self.bootstrap()
        return self.__dict__['post_bootstrap']

    def _update_proto(self, proto):
        """
        internal method, used by launch_tor to update the protocol after we're set up.
        """
        self.__dict__['_protocol'] = proto

    def __setattr__(self, name, value):
        """
        we override this so that we can provide direct attribute
        access to our config items, and move them into self.unsaved
        when they've been changed. hiddenservices have to be special
        unfortunately. the _setup_ thing is so that we can set up the
        attributes we need in the constructor without uusing __dict__
        all over the place.
        """

        if '_setup_' in self.__dict__:
            name = self._find_real_name(name)
            if '_slutty_' not in self.__dict__ and name.lower() != 'hiddenservices':
                value = self.parsers[name].validate(value, self, name)
            if isinstance(value, types.ListType):
                value = _ListWrapper(value, functools.partial(self.mark_unsaved, name))

            name = self._find_real_name(name)
            self.unsaved[name] = value

        else:
            super(TorConfig, self).__setattr__(name, value)

    def __getattr__(self, name):
        """
        on purpose, we don't return self.saved if the key is in there
        because I want the config to represent the running Tor not
        ``things which might get into the running Tor if save() were
        to be called''
        """

        rn = self._find_real_name(name)
        if '_slutty_' in self.__dict__ and rn in self.unsaved:
            return self.unsaved[rn]
        return self.config[rn]

    def __contains__(self, item):
        if item in self.unsaved and '_slutty_' in self.__dict__:
            return True
        return item in self.config

    def __iter__(self, *args, **kw):
        '''
        FIXME should work with .saved as well!
        ...and needs proper iterator tests in test_torconfig too
        '''
        return self.config.__iter__(*args, **kw)

    def get_type(self, name):
        """
        return the type of a config key.

        :param: name the key

        FIXME can we do something more-clever than this for client
        code to determine what sort of thing a key is?
        """

        if name.lower() == 'hiddenservices':
            return HiddenService
        return type(self.parsers[name])

    def _conf_changed(self, arg):
        """
        internal callback. from control-spec:

        4.1.18. Configuration changed

          The syntax is:
             StartReplyLine *(MidReplyLine) EndReplyLine

             StartReplyLine = "650-CONF_CHANGED" CRLF
             MidReplyLine = "650-" KEYWORD ["=" VALUE] CRLF
             EndReplyLine = "650 OK"

          Tor configuration options have changed (such as via a SETCONF or RELOAD
          signal). KEYWORD and VALUE specify the configuration option that was changed.
          Undefined configuration options contain only the KEYWORD.
        """

        conf = parse_keywords(arg, multiline_values=False)
        for (k, v) in conf.items():
            ## v will be txtorcon.DEFAULT_VALUE already from
            ## parse_keywords if it was unspecified
            self.config[self._find_real_name(k)] = v

    def bootstrap(self, arg=None):
        '''
        This only takes args so it can be used as a callback. Don't
        pass an arg, it is ignored.
        '''
        try:
            self.protocol.add_event_listener('CONF_CHANGED', self._conf_changed)
        except RuntimeError:
            ## for Tor versions which don't understand CONF_CHANGED
            ## there's nothing we can really do.
            log.msg("Can't listen for CONF_CHANGED event; won't stay up-to-date with other clients.")
        d = self.protocol.get_info_raw("config/names")
        d.addCallbacks(self._do_setup, log.err)
        d.addCallback(self.do_post_bootstrap)
        d.addErrback(self.do_post_errback)

    def do_post_errback(self, fail):
        self.post_bootstrap.errback(fail)
        self.__dict__['post_bootstrap'] = None
        return None

    def do_post_bootstrap(self, arg):
        self.post_bootstrap.callback(self)
        self.__dict__['post_bootstrap'] = None
        return self

    def needs_save(self):
        return len(self.unsaved) > 0

    def mark_unsaved(self, name):
        name = self._find_real_name(name)
        if name in self.config and name not in self.unsaved:
            self.unsaved[name] = self.config[self._find_real_name(name)]

    def save(self):
        """
        Save any outstanding items. This returns a Deferred which will
        errback if Tor was unhappy with anything, or callback with
        this TorConfig object on success.
        """

        if not self.needs_save():
            return defer.succeed(self)

        args = []
        for (key, value) in self.unsaved.items():
            if key == 'HiddenServices':
                self.config['HiddenServices'] = value
                for hs in value:
                    args.append('HiddenServiceDir')
                    args.append(hs.dir)
                    for p in hs.ports:
                        args.append('HiddenServicePort')
                        args.append(str(p))
                    if hs.version:
                        args.append('HiddenServiceVersion')
                        args.append(str(hs.version))
                    if hs.authorize_client:
                        args.append('HiddenServiceAuthorizeClient')
                        args.append(hs.authorize_client)
                continue

            if isinstance(value, types.ListType):
                for x in value:
                    args.append(key)
                    args.append(str(x))

            else:
                args.append(key)
                args.append(value)

            # FIXME in future we should wait for CONF_CHANGED and
            # update then, right?
            self.config[self._find_real_name(key)] = value

        ## FIXME might want to re-think this, but currently there's no
        ## way to put things into a config and get them out again
        ## nicely...unless you just don't assign a protocol
        if self.protocol:
            d = self.protocol.set_conf(*args)
            d.addCallback(self._save_completed)
            d.addErrback(log.err)
            return d

        else:
            self._save_completed()
            return defer.succeed(self)

    def _save_completed(self, *args):
        '''internal callback'''
        self.__dict__['unsaved'] = {}
        return self

    def _find_real_name(self, name):
        for x in self.__dict__['config'].keys():
            if x.lower() == name:
                return x
        return name

    @defer.inlineCallbacks
    def _do_setup(self, data):
        for line in data.split('\n'):
            if line == "config/names=":
                continue

            (name, value) = line.split()
            if name == 'HiddenServiceOptions':
                ## set up the "special-case" hidden service stuff
                servicelines = yield self.protocol.get_conf_raw('HiddenServiceOptions')
                self._setup_hidden_services(servicelines)
                continue

            if value == 'Dependant':
                continue

            ## there's a thing called "Boolean+Auto" which is -1 for
            ## auto, 0 for false and 1 for true. could be nicer if it
            ## was called AutoBoolean or something, but...
            value = value.replace('+', '_')

            inst = None
            # FIXME: put parser classes in dict instead?
            for cls in config_types:
                if cls.__name__ == value:
                    inst = cls()
            if not inst:
                raise RuntimeError("Don't have a parser for: " + value)
            v = yield self.protocol.get_conf(name)
            v = v[name]

            self.parsers[name] = inst

            if value == 'LineList':
                ## FIXME should move to the parse() method, but it
                ## doesn't have access to conf object etc.
                self.config[self._find_real_name(name)] = _ListWrapper(self.parsers[name].parse(v), functools.partial(self.mark_unsaved, name))

            else:
                self.config[self._find_real_name(name)] = self.parsers[name].parse(v)

        # can't just return in @inlineCallbacks-decorated methods
        defer.returnValue(self)

    def _setup_hidden_services(self, servicelines):
        hs = []
        directory = None
        ports = []
        ver = None
        auth = None
        for line in servicelines.split('\n'):
            if not len(line.strip()):
                continue

            if line == 'HiddenServiceOptions':
                continue
            k, v = line.split('=')
            if k == 'HiddenServiceDir':
                if directory is not None:
                    hs.append(HiddenService(self, directory, ports, auth, ver))
                directory = v
                ports = []
                ver = None
                auth = None

            elif k == 'HiddenServicePort':
                ports.append(v)

            elif k == 'HiddenServiceVersion':
                ver = int(v)

            elif k == 'HiddenServiceAuthorizeClient':
                auth = v

            else:
                raise RuntimeError("Can't parse HiddenServiceOptions: " + k)

        if directory is not None:
            hs.append(HiddenService(self, directory, ports, auth, ver))

        name = 'HiddenServices'
        self.config[name] = _ListWrapper(hs, functools.partial(self.mark_unsaved, name))

    def create_torrc(self):
        rtn = StringIO()

        for (k, v) in self.config.items() + self.unsaved.items():
            if type(v) is _ListWrapper:
                if k.lower() == 'hiddenservices':
                    for x in v:
                        for (kk, vv) in x.config_attributes():
                            rtn.write('%s %s\n' % (kk, vv))

                else:
                    for x in v:
                        rtn.write('%s %s\n' % (k, x))

            else:
                rtn.write('%s %s\n' % (k, v))

        return rtn.getvalue()
