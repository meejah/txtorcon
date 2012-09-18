from __future__ import with_statement

from twisted.python import log, failure
from twisted.internet import defer, error, protocol
from twisted.internet.interfaces import IProtocolFactory, IStreamServerEndpoint
from twisted.internet.endpoints import TCP4ClientEndpoint, TCP4ServerEndpoint
from twisted.protocols.basic import LineOnlyReceiver
from zope.interface import implements

## outside this module, you can do "from txtorcon import Stream" etc.
from txtorcon.stream import Stream
from txtorcon.circuit import Circuit
from txtorcon.router import Router
from txtorcon.addrmap import AddrMap
from txtorcon.torcontrolprotocol import parse_keywords, DEFAULT_VALUE, TorProtocolFactory
from txtorcon.util import delete_file_or_tree, find_keywords
from txtorcon.log import txtorlog

from txtorcon.interface import ITorControlProtocol, IRouterContainer, ICircuitListener
from txtorcon.interface import ICircuitContainer, IStreamListener, IStreamAttacher
from spaghetti import FSM, State, Transition

import os
import sys
import string
import itertools
import types
import functools
import random
import tempfile
from StringIO import StringIO
import shlex


class TCPHiddenServiceEndpoint(object):
    """
    This represents something listening on an arbitrary local port
    that has a Tor configured with a Hidden Service pointing at
    it. :api:`twisted.internet.endpoints.TCP4ServerEndpoint
    <TCP4ServerEndpoint>` is used under the hood to do the local
    listening.

    :ivar onion_uri: the public key, like `timaq4ygg2iegci7.onion`
        which came from the data_dir's `hostname` file

    :ivar onion_private_key: the contents of `data_dir/private_key`

    :ivar data_dir: the data directory, either passed in or created
        with `tempfile.mkstemp`

    :ivar public_port: the port we are advertising
    """

    implements(IStreamServerEndpoint)

    def __init__(self, reactor, config, public_port, data_dir=None,
                 port_generator=functools.partial(random.randrange, 1024, 65534),
                 endpoint_generator=TCP4ServerEndpoint):
        """
        :param reactor:
            :api:`twisted.internet.interfaces.IReactorTCP` provider

        :param config:
            :class:`txtorcon.TorConfig` instance (doesn't need to be
            bootstrapped). Note that `save()` will be called on this
            at least once. FIXME should I just accept a
            TorControlProtocol instance instead, and create my own
            TorConfig?

        :param public_port:
            The port number we will advertise in the hidden serivces
            directory.

        :param data_dir:
            The hidden-service data directory; if None, one will be
            created in /tmp. This contains the public + private keys
            for the onion uri. If you didn't specify a directory, it's
            up to you to save the public/private keys later if you
            want to re-launch the same hidden service at a different
            time.

        :param port_generator:
            A callable that generates a new random port to try
            listening on. Defaults to `random.randrange(1024, 65535)`

        :param endpoint_generator:
            A callable that generates a new instance of something that
            implements IServerEndpoint (by default TCP4ServerEndpoint)
        """

        self.public_port = public_port
        self.data_dir = data_dir
        self.onion_uri = None
        self.onion_private_key = None
        if self.data_dir is not None:
            self._update_onion()

        else:
            self.data_dir = tempfile.mkdtemp(prefix='tortmp')

        # shouldn't need to use these
        self.reactor = reactor
        self.config = config
        self.hiddenservice = None
        self.port_generator = port_generator
        self.endpoint_generator = endpoint_generator

        self.retries = 0

        self.defer = defer.Deferred()

    def _update_onion(self):
        """
        Used internally to update the `onion_uri` and
        `onion_private_key` members.
        """

        hn = os.path.join(self.hiddenservice.dir, 'hostname')
        pk = os.path.join(self.hiddenservice.dir, 'private_key')
        try:
            with open(hn, 'r') as hnfile:
                self.onion_uri = hnfile.read().strip()
        except IOError:
            self.onion_uri = None

        try:
            with open(pk, 'r') as pkfile:
                self.onion_private_key = pkfile.read().strip()
        except IOError:
            self.onion_private_key = None

    def _create_hiddenservice(self, arg):
        """
        Internal callback to create a hidden-service config in the
        running Tor (via the `config` member).
        """

        ## FIXME this should be anything that doesn't currently have a
        ## listener, and we should check that....or keep trying random
        ## ports if the "real" listen fails?
        self.listen_port = 80

        self.hiddenservice = HiddenService(self.config, self.data_dir,
                                           ['%d 127.0.0.1:%d' % (self.public_port,
                                                                 self.listen_port)])
        self.config.HiddenServices.append(self.hiddenservice)
        return arg

    def _do_error(self, f):
        """
        handle errors. FIXME
        """

        print "ERROR", f
        return f

    def listen(self, protocolfactory):
        """
        Implement :api:`twisted.internet.interfaces.IStreamServerEndpoint <IStreamServerEndpoint>`.

        Returns a Deferred that delivers an
        :api:`twisted.internet.interfaces.IPort` instance that also
        has at least `onion_uri` and `onion_private_key` members set
        (both strings). Really this is just what
        :api:`twisted.internet.endpoint.TCP4ServerEndpoint
        <TCP4ServerEndpoint>` returned, with a few members set. At
        this point, Tor will have fully started up and successfully
        accepted the hidden service's config.
        """

        self.protocolfactory = protocolfactory
        if self.config.post_bootstrap:
            d = self.config.post_bootstrap.addCallback(self._create_hiddenservice).addErrback(self._do_error)

        elif self.hiddenservice is None:
            self._create_hiddenservice(None)
            d = self.config.save()

        else:
            raise RuntimeError("FIXME")

        d.addCallback(self._create_listener).addErrback(self._retry_local_port)
        return d

    def _retry_local_port(self, failure):
        """
        Handles :api:`twisted.internet.error.CannotListenError` by
        trying again on another port. After 10 failures, we give up
        and propogate the error.
        """
        failure.trap(error.CannotListenError)

        self.retries += 1
        if self.retries > 10:
            return failure
        self.listen_port = self.port_generator()
        ## we do want to overwrite the whole list, not append
        self.hiddenservice.ports = ['%d 127.0.0.1:%d' % (self.public_port,
                                                         self.listen_port)]
        d = self.config.save()
        d.addCallback(self._create_listener).addErrback(self._retry_local_port)
        return d

    def _create_listener(self, proto):
        """
        Creates the local TCP4ServerEndpoint instance, returning a
        Deferred delivering an IPort instance that also has
        :meth:`TCP4HiddenServiceEndpoint._add_attributes` called
        against it (adds `onion_uri` and `onion_private_key` members).
        """

        self._update_onion()

        self.tcp_endpoint = TCP4ServerEndpoint(self.reactor, self.listen_port)
        d = self.tcp_endpoint.listen(self.protocolfactory)
        d.addCallback(self._add_attributes).addErrback(self._retry_local_port)
        return d

    def _add_attributes(self, port):
        port.onion_uri = self.onion_uri
        port.onion_port = self.public_port
        return port


class TorProcessProtocol(protocol.ProcessProtocol):

    def __init__(self, connection_creator, progress_updates=None):
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

        :ivar tor_protocol: The TorControlProtocol instance connected
            to the Tor this :api:`twisted.internet.protocol.ProcessProtocol <ProcessProtocol>`` is speaking to. Will be valid
            when the `connected_cb` callback runs.

        :ivar connected_cb: Triggered when the Tor process we
            represent is fully bootstrapped

       """

        self.tor_protocol = None
        self.connection_creator = connection_creator
        self.progress_updates = progress_updates

        self.connected_cb = defer.Deferred()

        self.attempted_connect = False
        self.to_delete = []
        self.stderr = []
        self.stdout = []

    def outReceived(self, data):
        """
        :api:`twisted.internet.protocol.ProcessProtocol <ProcessProtocol>` API
        """

        self.stdout.append(data)

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

    def errReceived(self, data):
        """
        :api:`twisted.internet.protocol.ProcessProtocol <ProcessProtocol>` API
        """

        self.stderr.append(data)
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

        if isinstance(status.value, error.ProcessDone):
            return

        raise RuntimeError('\n'.join(self.stdout) + "\n\nTor exited with error-code %d" % status.value.exitCode)

    def progress(self, percent, tag, summary):
        """
        Can be overridden or monkey-patched if you want to get
        progress updates yourself.
        """

        if self.progress_updates:
            self.progress_updates(percent, tag, summary)

    ## the below are all callbacks

    def tor_connection_failed(self, fail):
        ## FIXME more robust error-handling please, like a timeout so
        ## we don't just wait forever after 100% bootstrapped (that
        ## is, we're ignoring these errors, but shouldn't do so after
        ## we'll stop trying)
        self.attempted_connect = False
        return None

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
            self.connected_cb.callback(self)

    def tor_connected(self, proto):
        txtorlog.msg("tor_connected %s" % proto)

        self.tor_protocol = proto
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
               tor_binary='/usr/sbin/tor',
               progress_updates=None,
               connection_creator=None):
    """
    launches a new Tor process with the given config.

    If Tor prints anything on stderr, we kill off the process, close
    the TorControlProtocol and raise an exception.

    :param config: an instance of :class:`txtorcon.TorConfig` with any
        configuration values you want. :meth:`txtorcon.TorConfig.save`
        should have been called already (anything unsaved won't make
        it into the torrc produced). If ControlPort isn't set, 9052 is
        used; if DataDirectory isn't set, tempdir is used to create
        one.

    :param reactor: a Twisted IReactorCore implementation (usually
        twisted.internet.reactor)

    :param tor_binary: path to the Tor binary to run.

    :param progress_updates: a callback which gets progress updates; gets as
         args: percent, tag, summary (FIXME make an interface for this).

    :param connection_creator: is mostly available to ease testing, so
        you probably don't want to supply this. If supplied, it is a
        callable that should return a Deferred that delivers an
        :api:`twisted.internet.interfaces.IProtocol <IProtocol>` or ConnectError.
        See :api:`twisted.internet.interfaces.IStreamClientEndpoint`.connect

    :return: a Deferred which callbacks with a TorProcessProtocol
        connected to the fully-bootstrapped Tor; this has a
        :class:`txtorcon.TorControlProtocol` instance as .protocol. In Tor,
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

    if config.needs_save():
        log.msg("Config was unsaved when launch_tor() called; calling save().")
        config.save()

    try:
        data_directory = config.DataDirectory
        user_set_data_directory = True
    except KeyError:
        user_set_data_directory = False
        data_directory = tempfile.mkdtemp(prefix='tortmp')
        config.DataDirectory = data_directory

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
    process_protocol = TorProcessProtocol(connection_creator, progress_updates)

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
        transport = reactor.spawnProcess(process_protocol, tor_binary,
                                         args=(tor_binary, '-f', torrc),
                                         env={'HOME': data_directory},
                                         path=data_directory)
        #FIXME? don't need rest of the args: uid, gid, usePTY, childFDs)
        transport.closeStdin()

    except RuntimeError, e:
        process_protocol.connected_cb.errback(e)

    return process_protocol.connected_cb


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
        Helper method used by y TorConfig when generating a torrc file.
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
    present. This is done with lazy caching: the first time you access
    a value, it asks the underlying Tor (via TorControlProtocol) and
    thereafter caches the value; if you change it, a SETCONF is
    issued.

    When setting configuration values, they are cached locally and DO
    NOT AFFECT the running Tor until you call save(). When getting
    config items they will reflect the current state of Tor
    (i.e. *not* what's been set since the last save())

    Note that you do not need to call save() if you're just using
    TorConfig to create a .torrc file or for input to launch_tor().

    FIXME: It also listens on the CONF_CHANGED event to update the
    cached data in the event other controllers (etc) changed it. (Only
    exists in Git versions?)

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
        if control is None:
            self.protocol = None
            self.__dict__['_slutty_'] = None
        else:
            self.protocol = ITorControlProtocol(control)

        self.config = {}
        '''Current configuration, by keys.'''

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

        return self.config[self._find_real_name(name)]

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

    def bootstrap(self, *args):
        try:
            self.protocol.add_event_listener('CONF_CHANGED', self._conf_changed)
        except (RuntimeError, e):
            ## for Tor versions which don't understand CONF_CHANGED
            ## there's nothing we can really do.
            log.msg("Can't listen for CONF_CHANGED event; won't stay up-to-date with other clients.")
        return self.protocol.get_info_raw("config/names").addCallbacks(self._do_setup, log.err).addCallback(self.do_post_bootstrap).addErrback(log.err)

    def do_post_bootstrap(self, *args):
        self.post_bootstrap.callback(self)
        self.__dict__['post_bootstrap'] = None

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
            if line == "config/names=" or line == "OK":
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
