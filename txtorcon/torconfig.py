# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function
from __future__ import with_statement

import os
import re
import sys
import types
import functools
import warnings
from io import StringIO

from twisted.python import log
from twisted.internet import defer

from txtorcon.torcontrolprotocol import parse_keywords, DEFAULT_VALUE
from txtorcon.util import find_keywords
from txtorcon.interface import ITorControlProtocol

from zope.interface import Interface, Attribute, implementer


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
    "Boolean values are stored as 0 or 1."
    def parse(self, s):
        if int(s):
            return True
        return False

    def validate(self, s, instance, name):
        if s:
            return 1
        return 0


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

    def validate(self, s, instance, name):
        # FIXME: Is 'auto' an allowed value? (currently not)
        s = int(s)
        if s < 0:
            return 'auto'
        elif s:
            return 1
        else:
            return 0


class Integer(TorConfigType):
    def parse(self, s):
        return int(s)

    def validate(self, s, instance, name):
        return int(s)


class SignedInteger(Integer):
    pass


class Port(Integer):
    pass


class TimeInterval(Integer):
    pass


# not actually used?
class TimeMsecInterval(TorConfigType):
    pass


class DataSize(Integer):
    pass


class Float(TorConfigType):
    def parse(self, s):
        return float(s)


# unused also?
class Time(TorConfigType):
    pass


class CommaList(TorConfigType):
    def parse(self, s):
        return [x.strip() for x in s.split(',')]


# FIXME: in latest master; what is it?
# Tor source says "A list of strings, separated by commas and optional
# whitespace, representing intervals in seconds, with optional units"
class TimeIntervalCommaList(CommaList):
    pass


# FIXME: is this really a comma-list?
class RouterList(CommaList):
    pass


class String(TorConfigType):
    pass


class Filename(String):
    pass


class LineList(TorConfigType):
    def parse(self, s):
        if isinstance(s, list):
            return [str(x).strip() for x in s]
        return [x.strip() for x in s.split('\n')]

    def validate(self, obj, instance, name):
        if not isinstance(obj, list):
            raise ValueError("Not valid for %s: %s" % (self.__class__, obj))
        return _ListWrapper(
            obj, functools.partial(instance.mark_unsaved, name))

config_types = [Boolean, Boolean_Auto, LineList, Integer, SignedInteger, Port,
                TimeInterval, TimeMsecInterval,
                DataSize, Float, Time, CommaList, String, LineList, Filename,
                RouterList, TimeIntervalCommaList]


def is_list_config_type(klass):
    return 'List' in klass.__name__ or klass.__name__ in ['HiddenServices']


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


class HiddenServiceClientAuth(object):
    """
    Encapsulates a single client-authorization, as parsed from a
    HiddenServiceDir's "client_keys" file if you have stealth or basic
    authentication turned on.

    :param name: the name you gave it in the HiddenServiceAuthorizeClient line
    :param cookie: random password
    :param key: RSA private key, or None if this was basic auth
    """

    def __init__(self, name, cookie, key=None):
        self.name = name
        self.cookie = cookie
        self.key = parse_rsa_blob(key) if key else None


class IOnionService(Interface):
    """
    Encapsulates a single, ephemeral onion service.

    If this happens to be a filesystem-based service (instead of
    ephemeral), it shall implement IFilesystemOnionService as well.

    If this object happens to represent an authenticated service, it
    shall implement IAuthenticatedOnionService ONLY (not this
    interface too; IAuthenticatedOnionService returns *lists* of
    IAuthenticatedOnionClient instances which are a subclass of
    IOnionService; see :class:`txtorcon.IAuthenticatedOnionService`).

    For non-authenticated services, there will be one of these per
    directory (i.e. HiddenServiceDir) if using non-ephemeral services,
    or one per ADD_ONION for ephemeral hidden services.

    For authenticated services, there is an instance implementing this
    interface for each "client" of the authenticated service. In the
    "basic" case, the .onion URI happens to be the same for each one
    (with a different authethentication token) whereas for a "stealth"
    sevice the .onion URI is different.
    """
    hostname = Attribute("hostname, including .onion") # XXX *with* .onion? or not?
    private_key = Attribute("Private key blob (bytes)")
    ports = Attribute("list of str; the ports lines like 'public_port host:local_port'")


#class IFilesystemOnionService(Interface):
class IFilesystemOnionService(IOnionService):
    # XXX do we want to expose the directory in the API? probably...
    hidden_service_directory = Attribute('The directory where private data is kept')
    group_readable = Attribute("set HiddenServiceGroupReadable if true")


class IAuthenticatedService(Interface):
    name = Attribute("which client is this")
    auth_token = Attribute("the keyz!!!")


@implements(IFilesystemOnionService)
@implements(IAuthencitaedService)
class AuthenticatedFilesystemOnionService(object):
    pass


@implements(IFilesystemOnionService)
class FilesystemOnionService(object):
    pass


# XXX bad name? why isn't it something collection-releated
# e.g. IOnionServiceCollection ... or whatever bikeshed color
# just having "OnionSerivce" in this class name smells real bad, because it doesn't implement IOnionService
# maybe: IOnionClients? IOnionClientCollection?
##class IAuthenticatedOnionService(Interface):

class IOnionClients(Interface):
    """
    This encapsulates both 'stealth' and 'basic' authenticated Onion
    (nee Hidden) services, whether ephemeral or not. Note that Tor
    doesn't yet support ephemeral authenticated services.
    """

    def client_names(self):
        """
        :return: list of str instances, one for each client
        """

    def get_client(self, name):
        """
        :return: object implementing IOnionClient for the named client
        """

    def add_client(self, name):
        """
        probably returns a Deferred? god fucking knows
        """

    def del_client(self, name):
        """
        moar deferreds
        """


class IOnionClient(IOnionService):
    """
    A single client from a 'parent' IAuthenticatedOnionService. We do
    this because hidden services can have different URLs and/or
    auth_tokens on a per-client basis. So, the only way to access
    *anything* from an authenticated onion service is to list the
    cleints -- which gives you one IAuthenticatedOnionClient per
    client.
    """
    auth_token = Attribute('Some secret bytes')
    name = Attribute('str') # XXX required? probably.
    # XXX do we want/need to reveal the "parent"
#    parent = Attribute("XXX?")


@implementer(IOnionService)
@implementer(IFilesystemOnionService)
class FilesystemHiddenService(object):
    """
    """
    def __init__(self, config, thedir, ports,
                 auth=None, ver=2, group_readable=0):
        if not isinstance(ports, list):
            raise ValueError("'ports' must be a list of strings")
        self._config = config
        self._dir = thedir
        self._ports = _ListWrapper(
            ports,
            functools.partial(config.mark_unsaved, 'HiddenServices'),
        )
        self._auth = auth
        if self._auth is None:
            self._auth = []
        else:
            print("AZXCASDFASDFASDFASDF", auth)
        self._version = ver
        self._group_readable = group_readable
        self._hostname = None
        self._private_key = None

    @property
    def auth_token(self):
        raise ValueError("FIXME")
    # can we reconcile this with the current API!? will NOT work for
    # stealth auth unless we fuxor around and make HiddenService
    # implement both interfaces :/

    @property
    def hostname(self):
        if self._hostname is None:
            with open(os.path.join(self._dir, 'hostname'), 'r') as f:
                self._hostname = f.read().strip()
        return self._hostname

    @property
    def private_key(self):
        if self._private_key is None:
            with open(os.path.join(self._dir, 'private_key'), 'r') as f:
                self._private_key = f.read().strip()
        return self._private_key

    @property
    def ports(self):
        return self._ports

    @ports.setter
    def ports(self, ports):
        # XXX FIXME need to update Tor's notion of config and/or
        # reject this request after we *have* updated Tor..."or
        # something"
        self._ports = _ListWrapper(
            ports,
            functools.partial(self._config.mark_unsaved, 'HiddenServices'),
        )
        self._config.mark_unsaved('HiddenServices')
        print("BOOOOMO", ports, self._ports, self)

    @property
    def dir(self):  # XXX propbably should be 'directory'?
        return self._dir

    @dir.setter
    def dir(self, d):
        self._dir = d # XXX FIXME see above
        self._config.mark_unsaved('HiddenServices')

    @property
    def group_readable(self):
        return self._group_readable

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, v):
        self._version = v
        self._config.mark_unsaved('HiddenServices')

    @property
    def authorize_client(self):
        return self._auth

    # etcetc, basically the old "HiddenService" object

    def config_attributes(self):
        # XXX probably have to switch to "get_config_commands" or similar?
        # -> how to do ADD_ONION stuff, anyway?
        # -> hmm, could do helper methods, NOT member func

        rtn = [('HiddenServiceDir', str(self.dir))]
        if self._config._supports['HiddenServiceDirGroupReadable'] \
           and self.group_readable:
            rtn.append(('HiddenServiceDirGroupReadable', str(1)))
        for x in self.ports:
            rtn.append(('HiddenServicePort', str(x)))
        if self.version:
            rtn.append(('HiddenServiceVersion', str(self.version)))
        for authline in self.authorize_client:
            print("XXX", authline)
            rtn.append(('HiddenServiceAuthorizeClient', str(authline)))
            #rtn.append(('HiddenServiceAuthorizeClient', str(self.authorize_client)))
        return rtn

    def config_commands(self):
        pass # XXX FIXME


# XXX: probably better/nicer to make "EphemeralHiddenService" object
# "just" a data-container; it needs to list-wrapping voodoo etc like
# the others.
#   --> so only way to "add" it to a Tor is via a factory-method (like
#       from_ports() below, but with a better name)
#   --> so possibly only from create_onion_service()
#   --> ...which itself shold probably be "just" a dispatcher to "more
#       specific" factory-functions, like "create_ephemeral_onion"
#       "create_detached_onion" "create_permanent_onion??" etc...?

@implementer(IOnionService)
class EphemeralHiddenService(object):
    @classmethod
    @defer.inlineCallbacks
    def create(cls, config, ports,
               detach=False,
               discard_key=False,
               private_key=None):
        """
        returns a new EphemeralHiddenService after adding it to the
        provided config and ensuring at least one of its descriptors
        is uploaded.

        See also :meth:`txtorcon.create_onion_service` (which
        ultimately calls this).
        """
        if private_key and discard_key:
            raise ValueError("Don't pass a 'private_key' and ask to 'discard_key'")

        onion = EphemeralHiddenService(
            config, ports,
            hostname=None,
            private_key=private_key,
            detach=detach,
            discard_key=discard_key,
        )
        # XXX just use sets for this instead of lists?
        if onion not in config.EphemeralOnionServices:
            config.EphemeralOnionServices.append(onion)

        # we need to wait for confirmation that we've published the
        # descriptor to at least one Directory Authority. This means
        # watching the 'HS_DESC' event, but we do that right *before*
        # issuing the ADD_ONION command(s) so we can't miss one.
        uploaded = defer.Deferred()
        attempted_uploads = set()
        confirmed_uploads = set()
        failed_uploads = set()

        def hs_desc(evt):
            """
            From control-spec:
            "650" SP "HS_DESC" SP Action SP HSAddress SP AuthType SP HsDir
            [SP DescriptorID] [SP "REASON=" Reason] [SP "REPLICA=" Replica]
            """
            print("GODEVENT", evt)
            args = evt.split()
            subtype = args[0]
            if subtype == 'UPLOAD':
                if args[1] == onion.hostname[:-6]:
                    attempted_uploads.add(args[3])

            elif subtype == 'UPLOADED':
                # we only need ONE successful upload to happen for the
                # HS to be reachable.
                addr = args[1]
                if args[3] in attempted_uploads:
                    confirmed_uploads.add(args[3])
                    log.msg("Uploaded '{}' to '{}'".format(onion.hostname, args[3]))
                    uploaded.callback(onion)

            elif subtype == 'FAILED':
                if args[1] == onion.hostname[:-6]:
                    failed_uploads.add(args[3])
                    if failed_uploads == attempted_uploads:
                        msg = "Failed to upload '{}' to: {}".format(
                            onion.hostname,
                            ', '.join(failed_uploads),
                        )
                        uploaded.errback(RuntimeError(msg))

        yield config.tor_protocol.add_event_listener('HS_DESC', hs_desc)

        # okay, we're set up to listen, and now we issue the ADD_ONION
        # command. this will set ._hostname and ._private_key properly
        cmd = 'ADD_ONION {}'.format(onion.private_key or 'NEW:BEST')
        for port in ports:
            cmd += ' Port={},{}'.format(*port.split(' ', 1))
        flags = []
        if detach:
            flags.append('Detach')
        if discard_key:
            flags.append('DiscardPK')
        if flags:
            cmd += ' Flags={}'.format(','.join(flags))

        res = yield config.tor_protocol.queue_command(cmd)
        res = find_keywords(res.split('\n'))
        try:
            onion._hostname = res['ServiceID'] + '.onion'
            if discard_key:
                onion._private_key = None
            else:
                onion._private_key = res['PrivateKey']
        except KeyError:
            raise RuntimeError(
                "Expected ADD_ONION to return ServiceID= and PrivateKey= args"
            )

        log.msg("Created '{}', waiting for descriptor uploads.".format(onion.hostname))
        print("waiting for upload")
        yield uploaded
        print("UPLOADED!")
        yield config.tor_protocol.remove_event_listener('HS_DESC', hs_desc)
        print("removed")

        # XXX more thinking req'd
        #config.HiddenServices.append(onion)
        if onion not in config.EphemeralOnionServices:
            config.EphemeralOnionServices.append(onion)

        defer.returnValue(onion)
        return

    def __init__(self, config, ports, hostname=None, private_key=None, auth=[], ver=2,
                 detach=False, discard_key=False):
        # XXX do we need version?
        self._config = config
        self._ports = ports
        self._hostname = hostname
        self._private_key = private_key
        self._detach = detach
        self._discard_key = discard_key
        if auth != []:
            raise RuntimeError(
                "Tor doesn't yet support authentication on ephemeral onion "
                "services."
            )
        self._version = ver

    @property
    def hostname(self):
        return self._hostname

    @property
    def private_key(self):
        return self._private_key

    # Note: auth not yet supported by Tor, for ADD_ONION


@implementer(IOnionService)
class AuthenticatedHiddenServiceClient(object):
    """
    A single client of an AuthenticatedHiddenService

    These are only created by and returned from the .clients property
    of an AuthenticatedHiddenService instance.
    """

    def __init__(self, parent, name, hostname, ports, token):
        self._parent = parent
        self._name = name
        self.hostname = hostname
        self.auth_token = token
        self.ephemeral = False
        self._ports = ports
        # XXX private_key?
        # XXX group_readable

    @property
    def ports(self):
        return self._ports

    @property
    def private_key(self):
        # yes, needs to come from "clients" file i think?
        return self._parent._private_key(self._name).key

    @property
    def group_readable(self):
        return self._parent.group_readable


@implementer(IAuthenticatedOnionService)
class AuthenticatedHiddenService(object):
    """
    Corresponds to::

      HiddenServiceDir /home/mike/src/tor/hidserv-stealth
      HiddenServiceDirGroupReadable 1
      HiddenServicePort 80 127.0.0.1:99
      HiddenServiceAuthorizeClient stealth quux,flummox,zinga

    or::

      HiddenServiceDir /home/mike/src/tor/hidserv-basic
      HiddenServiceDirGroupReadable 1
      HiddenServicePort 80 127.0.0.1:99
      HiddenServiceAuthorizeClient basic foo,bar,baz
    """
    def __init__(self, config, thedir, ports, clients=None, ver=2, group_readable=0):
        # XXX do we need version here? probably...
        self._config = config
        self._dir = thedir
        self._ports = ports
        # dict: name -> IAuthenticatedOnionClient
        self._clients = None  # XXX validate vs. clients if not None?
        self._version = ver
        self._group_readable = group_readable
        self._client_keys = None

    # basically everything in HiddenService, except the only API we
    # provide is "clients" because there's a separate .onion hostname
    # and authentication token per client.

    def client_names(self):
        """
        IAuthenticatedOnionService API
        """
        if self._clients is None:
            self._parse_hostname()
        return self._clients.keys()

    def get_client(self, name):
        """
        IAuthenticatedOnionService API
        """
        if self._clients is None:
            self._parse_hostname()
        try:
            return self._clients[name]
        except KeyError:
            raise RuntimeError("No such client '{}'".format(name))

    def _private_key(self, name):
        if self._client_keys is None:
            self._parse_client_keys()
        return self._client_keys[name]

    def _parse_client_keys(self):
        with open(os.path.join(self._dir, 'client_keys'), 'r') as f:
            keys = parse_client_keys(f)
        self._client_keys = {}
        for auth in keys:
            self._client_keys[auth.name] = auth

    def _parse_hostname(self):
        clients = {}
        with open(os.path.join(self._dir, 'hostname')) as f:
            for idx, line in enumerate(f.readlines()):
                # lines are like: hex.onion hex # client: name
                m = re.match("(.*) (.*) # client: (.*)", line)
                print("DinG", m, line)
                hostname, cookie, name = m.groups()
                # -> for auth'd services we end up with multiple
                # -> HiddenService instances now (because different
                # -> hostnames)
                clients[name] = AuthenticatedHiddenServiceClient(
                    self, name, hostname,
                    ports=self._ports,
                    token=cookie,
                )
        self._clients = clients


    def config_attributes(self):
        """
        Helper method used by TorConfig when generating a torrc file.
        """

        rtn = [('HiddenServiceDir', str(self.dir))]
        if self.conf._supports['HiddenServiceDirGroupReadable'] \
           and self.group_readable:
            rtn.append(('HiddenServiceDirGroupReadable', str(1)))
        for port in self.ports:
            rtn.append(('HiddenServicePort', str(port)))
        if self.version:
            rtn.append(('HiddenServiceVersion', str(self.version)))
        for authline in self.authorize_client:
            rtn.append(('HiddenServiceAuthorizeClient', str(authline)))
        return rtn


def parse_rsa_blob(lines):
    return 'RSA1024:' + ''.join(lines[1:-1])


def parse_client_keys(stream):
    '''
    This parses a hidden-service "client_keys" file, either stealth or
    basic (they're the same, except "stealth" includes a
    "client-key"). Returns a list of HiddenServiceClientAuth() instances.

    Note that the key does NOT include the "----BEGIN ---" markers,
    nor *any* embedded whitespace. It is *just* the key blob.

    '''

    def parse_error(data):
        raise RuntimeError("Parse error at: " + data)

    class ParserState(object):
        def __init__(self):
            self.keys = []
            self.reset()

        def reset(self):
            self.name = None
            self.cookie = None
            self.key = []

        def create_key(self):
            if self.name is not None:
                self.keys.append(HiddenServiceClientAuth(self.name, self.cookie, self.key))
            self.reset()

        def set_name(self, name):
            self.create_key()
            self.name = name.split()[1]

        def set_cookie(self, cookie):
            self.cookie = cookie.split()[1]
            if self.cookie.endswith('=='):
                self.cookie = self.cookie[:-2]

        def add_key_line(self, line):
            self.key.append(line)

    from txtorcon.spaghetti import FSM, State, Transition
    init = State('init')
    got_name = State('got_name')
    got_cookie = State('got_cookie')
    reading_key = State('got_key')

    parser_state = ParserState()

    # initial state; we want "client-name" or it's an error
    init.add_transitions([
        Transition(got_name, lambda line: line.startswith('client-name '), parser_state.set_name),
        Transition(init, lambda line: not line.startswith('client-name '), parse_error),
    ])

    # next up is "descriptor-cookie" or it's an error
    got_name.add_transitions([
        Transition(got_cookie, lambda line: line.startswith('descriptor-cookie '), parser_state.set_cookie),
        Transition(init, lambda line: not line.startswith('descriptor-cookie '), parse_error),
    ])

    # the "interesting bit": there's either a client-name if we're a
    # "basic" file, or an RSA key (with "client-key" before it)
    got_cookie.add_transitions([
        Transition(reading_key, lambda line: line.startswith('client-key'), None),
        Transition(got_name, lambda line: line.startswith('client-name '), parser_state.set_name),
    ])

    # if we're reading an RSA key, we accumulate it in current_key.key
    # until we hit a line starting with "client-name"
    reading_key.add_transitions([
        Transition(reading_key, lambda line: not line.startswith('client-name'), parser_state.add_key_line),
        Transition(got_name, lambda line: line.startswith('client-name '), parser_state.set_name),
    ])

    # create our FSM and parse the data
    fsm = FSM([init, got_name, got_cookie, reading_key])
    for line in stream.readlines():
        fsm.process(line.strip())

    parser_state.create_key()  # make sure we get the "last" one
    return parser_state.keys


class OnionAuthNone(object):
    def __init__(self, uri):
        self._uri = uri

    def uri(self, client):
        if client is not None:
            msg = "client= specified for non-authenticated service"
            raise RuntimeError(msg)
        if self._uri is None:
            raise RuntimeError("No URI available yet")
        return self._uri


class OnionService(object):

    def __init__(self, torconfig, ports, is_ephemeral=True, authentication=None, directory=None):
        self.ports = ports
        self.ephemeral = is_ephemeral
        # private state:
        self._authentication = authentication
        if self._authentication is None:
            self._authentication = OnionAuthNone(None)
        self._tor_config = torconfig

    def uri(self, client=None):
        """
        Returns the onion URI for the given client. The client is only
        relevant for authenticated services.
        """
        return self._authentication.uri(client)


class TorConfig(object):
    """This class abstracts out Tor's config, and can be used both to
    create torrc files from nothing and track live configuration of a Tor
    instance.

    Also, it gives easy access to all the configuration options
    present. This is initialized at "bootstrap" time, providing
    attribute-based access thereafter. Note that after you set some
    number of items, you need to do a save() before these are sent to
    Tor (and then they will be done as one SETCONF).

    You may also use this class to construct a configuration from
    scratch (e.g. to give to :func:`txtorcon.launch_tor`). In this
    case, values are reflected right away. (If we're not bootstrapped
    to a Tor, this is the mode).

    Note that you do not need to call save() if you're just using
    TorConfig to create a .torrc file or for input to launch_tor().

    This class also listens for CONF_CHANGED events to update the
    cached data in the event other controllers (etc) changed it.

    There is a lot of magic attribute stuff going on in here (which
    might be a bad idea, overall) but the *intent* is that you can
    just set Tor options and it will all Just Work. For config items
    that take multiple values, set that to a list. For example::

        conf = TorConfig(...)
        conf.SOCKSPort = [9050, 1337]
        conf.HiddenServices.append(HiddenService(...))

    (Incoming objects, like lists, are intercepted and wrapped).

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

    @classmethod
    @defer.inlineCallbacks
    def from_protocol(cls, proto):
        """
        This creates and returns a ready-to-go TorConfig instance from the
        given protocol, which should be an instance of
        TorControlProtocol.
        """
        cfg = TorConfig(control=proto)
        yield cfg.post_bootstrap
        defer.returnValue(cfg)

    def __init__(self, control=None):
        self.config = {}
        '''Current configuration, by keys.'''

        if control is None:
            self._protocol = None
            self.__dict__['_slutty_'] = None

        else:
            self._protocol = ITorControlProtocol(control)

        self.unsaved = {}
        '''Configuration that has been changed since last save().'''

        self.parsers = {}
        '''Instances of the parser classes, subclasses of TorConfigType'''

        self.list_parsers = set(['hiddenservices', 'ephemeralonionservices'])
        '''All the names (keys from .parsers) that are a List of something.'''

        # during bootstrapping we decide whether we support the
        # following features. A thing goes in here if TorConfig
        # behaves differently depending upon whether it shows up in
        # "GETINFO config/names"
        self._supports = dict(
            HiddenServiceDirGroupReadable=False
        )

        self.post_bootstrap = defer.Deferred()
        if self.protocol:
            if self.protocol.post_bootstrap:
                self.protocol.post_bootstrap.addCallback(
                    self.bootstrap).addErrback(log.err)
            else:
                self.bootstrap()

        else:
            self.do_post_bootstrap(self)

        self.__dict__['_setup_'] = None

    def onion_create(self, ports, auth=None, directory=None, private_key=None):
        """
        Creates a new Onion service.

        :param ports: list of strings like "80 127.0.0.1:80"

        :param auth: None, or an IOnionAuthentication provider (in
            practice, an instance of :class:`OnionAuthBasic` or
            :class:`OnionAuthStealth`)

        :param directory: None means an ephemeral hidden service (the
            default). Otherwise, a "normal", persistent hidden-service
            using data in the provided directory (if the directory is
            empty, a new private key will be written there by Tor).

        :param private_key: If creating an ephemeral service, this can
            be provided. This will be something previously retrieved from
            the ``.private_key`` attribute of a HiddenService instance.

        :return: Deferred that fires with the HiddenService instance
            once it is configured.
        """
        # ephemeral service if directory is None
        # can't specify directory *and* private_key

    # FIXME should re-name this to "tor_protocol" to be consistent
    # with other things? Or rename the other things?
    """
    read-only access to TorControlProtocol. Call attach_protocol() to
    set it, which can only be done if we don't already have a
    protocol.
    """
    def _get_protocol(self):
        return self.__dict__['_protocol']
    protocol = property(_get_protocol)
    tor_protocol = property(_get_protocol)

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
        return self.__dict__['post_bootstrap']

    def _update_proto(self, proto):
        """
        internal method, used by launch_tor to update the protocol after we're
        set up.
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
        has_setup_attr = lambda o: '_setup_' in o.__dict__
        has_slutty_attr = lambda o: '_slutty_' in o.__dict__
        is_hidden_services = lambda s: s.lower() == "hiddenservices"

        if has_setup_attr(self):
            name = self._find_real_name(name)
            if not has_slutty_attr(self) and not is_hidden_services(name):
                value = self.parsers[name].validate(value, self, name)
            if isinstance(value, list):
                value = _ListWrapper(
                    value, functools.partial(self.mark_unsaved, name))

            name = self._find_real_name(name)
            self.unsaved[name] = value

        else:
            super(TorConfig, self).__setattr__(name, value)

    def _maybe_create_listwrapper(self, rn):
        if rn.lower() in self.list_parsers and rn not in self.config:
            self.config[rn] = _ListWrapper([], functools.partial(
                self.mark_unsaved, rn))

    def __getattr__(self, name):
        """
        on purpose, we don't return self.unsaved if the key is in there
        because I want the config to represent the running Tor not
        ``things which might get into the running Tor if save() were
        to be called''
        """
        rn = self._find_real_name(name)
        if '_slutty_' in self.__dict__ and rn in self.unsaved:
            return self.unsaved[rn]
        self._maybe_create_listwrapper(rn)
        return self.config[rn]

    def __contains__(self, item):
        if item in self.unsaved and '_slutty_' in self.__dict__:
            return True
        return item in self.config

    def __iter__(self):
        '''
        FIXME needs proper iterator tests in test_torconfig too
        '''
        for x in self.config.__iter__():
            yield x
        for x in self.__dict__['unsaved'].__iter__():
            yield x

    def get_type(self, name):
        """
        return the type of a config key.

        :param: name the key

        FIXME can we do something more-clever than this for client
        code to determine what sort of thing a key is?
        """

        # XXX FIXME uhm...how to do all the different types of hidden-services?
        if name.lower() == 'hiddenservices':
            return FilesystemHiddenService
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

          Tor configuration options have changed (such as via a SETCONF or
          RELOAD signal). KEYWORD and VALUE specify the configuration option
          that was changed.  Undefined configuration options contain only the
          KEYWORD.
        """

        conf = parse_keywords(arg, multiline_values=False)
        for (k, v) in conf.items():
            # v will be txtorcon.DEFAULT_VALUE already from
            # parse_keywords if it was unspecified
            real_name = self._find_real_name(k)
            if real_name in self.parsers:
                v = self.parsers[real_name].parse(v)
            self.config[real_name] = v

    def bootstrap(self, arg=None):
        '''
        This only takes args so it can be used as a callback. Don't
        pass an arg, it is ignored.
        '''
        print("BOOM! BOOTSTRAP")
        try:
            self.protocol.add_event_listener(
                'CONF_CHANGED', self._conf_changed)
        except RuntimeError:
            # for Tor versions which don't understand CONF_CHANGED
            # there's nothing we can really do.
            log.msg(
                "Can't listen for CONF_CHANGED event; won't stay up-to-date "
                "with other clients.")
        d = self.protocol.get_info_raw("config/names")
        d.addCallback(self._do_setup)
        d.addCallback(self.do_post_bootstrap)
        d.addErrback(self.do_post_errback)

    def do_post_errback(self, f):
        self.post_bootstrap.errback(f)
        return None

    def do_post_bootstrap(self, arg):
        if not self.post_bootstrap.called:
            self.post_bootstrap.callback(self)
        return self

    def needs_save(self):
        return len(self.unsaved) > 0

    def mark_unsaved(self, name):
        print("ZINGA markunsaved", name, self)
        name = self._find_real_name(name)
        print("xxxxx", name)
        if name in self.config and name not in self.unsaved:
            self.unsaved[name] = self.config[self._find_real_name(name)]
        print("unsaved now", self.unsaved, name, self.config)

    def save(self):
        """
        Save any outstanding items. This returns a Deferred which will
        errback if Tor was unhappy with anything, or callback with
        this TorConfig object on success.
        """

        if not self.needs_save():
            return defer.succeed(self)

        args = []
        directories = []
        for (key, value) in self.unsaved.items():
            if key == 'HiddenServices':
                self.config['HiddenServices'] = value
                for hs in value:
                    # XXX should use interface class instead
                    if not isinstance(hs, FilesystemHiddenService):
                        raise ValueError(
                            "Only txtorcon.HiddenService instances may be added"
                            " via TorConfig.hiddenservices; ephemeral services"
                            " must be created with 'create_onion_service'."
                        )
                    for (k, v) in hs.config_attributes():
                        if k == 'HiddenServiceDir':
                            if v not in directories:
                                directories.append(v)
                                args.append(k)
                                args.append(v)
                            else:
                                raise RuntimeError("Trying to add hidden service with same HiddenServiceDir: %s" % v)
                        else:
                            args.append(k)
                            args.append(v)
                continue

            if isinstance(value, list):
                for x in value:
                    # FIXME XXX
                    if x is not DEFAULT_VALUE:
                        args.append(key)
                        args.append(str(x))

            else:
                args.append(key)
                args.append(value)

            # FIXME in future we should wait for CONF_CHANGED and
            # update then, right?
            real_name = self._find_real_name(key)
            if not isinstance(value, list) and real_name in self.parsers:
                value = self.parsers[real_name].parse(value)
            self.config[real_name] = value

        print("AAAAARGZ", args, self.protocol)
        # FIXME might want to re-think this, but currently there's no
        # way to put things into a config and get them out again
        # nicely...unless you just don't assign a protocol
        if self.protocol:
            d = self.protocol.set_conf(*args)
            d.addCallback(self._save_completed)
            return d

        else:
            self._save_completed()
            return defer.succeed(self)

    def _save_completed(self, *args):
        '''internal callback'''
        self.__dict__['unsaved'] = {}
        return self

    def _find_real_name(self, name):
        keys = list(self.__dict__['parsers'].keys()) + list(self.__dict__['config'].keys())
        for x in keys:
            if x.lower() == name.lower():
                return x
        return name

    @defer.inlineCallbacks
    def _do_setup(self, data):
        for line in data.split('\n'):
            if line == "config/names=":
                continue

            (name, value) = line.split()
            if name in self._supports:
                self._supports[name] = True

            if name == 'HiddenServiceOptions':
                # set up the "special-case" hidden service stuff
                servicelines = yield self.protocol.get_conf_raw(
                    'HiddenServiceOptions')
                self._setup_hidden_services(servicelines)
                continue

            if value == 'Dependant':
                continue

            # there's a thing called "Boolean+Auto" which is -1 for
            # auto, 0 for false and 1 for true. could be nicer if it
            # was called AutoBoolean or something, but...
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

            rn = self._find_real_name(name)
            self.parsers[rn] = inst
            if is_list_config_type(inst.__class__):
                self.list_parsers.add(rn)
                parsed = self.parsers[rn].parse(v)
                self.config[rn] = _ListWrapper(
                    parsed, functools.partial(self.mark_unsaved, rn))

            else:
                self.config[rn] = self.parsers[rn].parse(v)

        # get any ephemeral services we own, or detached services.
        # these are *not* _ListWrappers because we don't care if they
        # change, nothing in Tor's config exists for these (probably
        # begging the question: why are we putting them in here at all
        # then...?)
        try:
            ephemeral = yield self.protocol.get_info('onions/current')
        except Exception:
            print("ZIMZAM0")
            self.config['EphemeralOnionServices'] = []
        else:
            onions = []
            for line in ephemeral['onions/current'].split('\n'):
                onion = line.strip()
                if onion:
                    onions.append(
                        EphemeralHiddenService(
                            self, None,  # no way to discover ports=
                            hostname=onion,
                            detach=False,
                            discard_key=True,  # we don't know it...
                        )
                    )
            print("ZIMZAM1")
            self.config['EphemeralOnionServices'] = onions

        try:
            detached = yield self.protocol.get_info('onions/detached')
        except Exception:
            self.config['DetachedOnionServices'] = []
        else:
            onions = []
            for line in detached['onions/detached'].split('\n'):
                onion = line.strip()
                if onion:
                    onions.append(
                        EphemeralHiddenService(
                            self, None, hostname=onion, detach=True,
                            discard_key=True,
                        )
                    )
            self.config['DetachedOnionServices'] = onions
        defer.returnValue(self)

    def _setup_hidden_services(self, servicelines):
        print("SETUP", servicelines)
        def maybe_add_hidden_service():
            if directory is not None:
                if directory not in directories:
                    directories.append(directory)
                    if not auth:
                        service = FilesystemHiddenService(
                            self, directory, ports, auth, ver, group_read
                        )
                        hs.append(service)
                    else:
                        print("AUTH", auth)
                        parent_service = AuthenticatedHiddenService(
                            self, directory, ports, auth, ver, group_read
                        )
                        for client_name in parent_service.client_names():
                            hs.append(parent_service.get_client(client_name))
                else:
                    raise RuntimeError("Trying to add hidden service with same HiddenServiceDir: %s" % directory)

        hs = []
        directory = None
        directories = []
        ports = []
        ver = None
        group_read = None
        auth = None
        for line in servicelines.split('\n'):
            if not len(line.strip()):
                continue

            if line == 'HiddenServiceOptions':
                continue
            k, v = line.split('=')
            if k == 'HiddenServiceDir':
                maybe_add_hidden_service()
                print("MAYBE!", v)
                directory = v
                _directory = directory
                directory = os.path.abspath(directory)
                if directory != _directory:
                    warnings.warn(
                        "Directory path: %s changed to absolute path: %s" % (_directory, directory),
                        RuntimeWarning
                    )
                ports = []
                ver = None
                auth = []
                group_read = 0

            elif k == 'HiddenServicePort':
                ports.append(v)

            elif k == 'HiddenServiceVersion':
                ver = int(v)

            elif k == 'HiddenServiceAuthorizeClient':
                auth.append(v)

            elif k == 'HiddenServiceDirGroupReadable':
                group_read = int(v)

            else:
                raise RuntimeError("Can't parse HiddenServiceOptions: " + k)

        maybe_add_hidden_service()

        name = 'HiddenServices'
        self.config[name] = _ListWrapper(
            hs, functools.partial(self.mark_unsaved, name))

    def config_args(self):
        '''
        Returns an iterator of 2-tuples (config_name, value), one for each
        configuration option in this config. This is more-or-less an
        internal method, but see, e.g., launch_tor()'s implementation
        if you think you need to use this for something.

        See :meth:`txtorcon.TorConfig.create_torrc` which returns a
        string which is also a valid ``torrc`` file
        '''

        for (k, v) in list(self.config.items()) + list(self.unsaved.items()):
            if type(v) is _ListWrapper:
                if k.lower() == 'hiddenservices':
                    for x in v:
                        for (kk, vv) in x.config_attributes():
                            yield (str(kk), str(vv))

                else:
                    # FIXME actually, is this right? don't we want ALL
                    # the values in one string?!
                    for x in v:
                        yield (str(k), str(x))

            else:
                yield (str(k), str(v))

    def create_torrc(self):
        rtn = StringIO()

        for (k, v) in self.config_args():
            rtn.write(u'%s %s\n' % (k, v))

        return rtn.getvalue()
