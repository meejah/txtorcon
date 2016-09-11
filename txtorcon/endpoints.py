# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function
from __future__ import with_statement

import os
import shutil
import weakref
import tempfile
import functools

from txtorcon.util import available_tcp_port

# backwards-compatibility dance: we "should" be using the
# ...WithReactor class, but in Twisted prior to 14, there is no such
# class (and the parse() doesn't provide a 'reactor' argument).
try:
    from twisted.internet.interfaces import IStreamClientEndpointStringParserWithReactor
    _HAVE_TX_14 = True
except ImportError:
    from twisted.internet.interfaces import IStreamClientEndpointStringParser as IStreamClientEndpointStringParserWithReactor
    _HAVE_TX_14 = False

try:
    from twisted.internet.ssl import optionsForClientTLS
    from txsocksx.tls import TLSWrapClientEndpoint
    _HAVE_TLS = True
except ImportError:
    _HAVE_TLS = False


from twisted.internet import defer, reactor
from twisted.python import log
from twisted.internet.interfaces import IStreamServerEndpointStringParser
from twisted.internet.interfaces import IStreamServerEndpoint
from twisted.internet.interfaces import IStreamClientEndpoint
from twisted.internet.interfaces import IListeningPort
from twisted.internet.interfaces import IAddress
from twisted.internet.endpoints import serverFromString
from twisted.internet.endpoints import clientFromString
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet import error
from twisted.plugin import IPlugin
from twisted.python.util import FancyEqMixin

from zope.interface import implementer
from zope.interface import Interface, Attribute

from txsocksx.client import SOCKS5ClientEndpoint

from .torconfig import TorConfig, launch_tor, HiddenService
from .torstate import build_tor_connection


_global_tor_config = None
_global_tor_lock = defer.DeferredLock()
# we need the lock because we (potentially) yield several times while
# "creating" the TorConfig instance


@defer.inlineCallbacks
def get_global_tor(reactor, control_port=None,
                   progress_updates=None,
                   _tor_launcher=lambda r, c, p: launch_tor(
                       c, r, progress_updates=p)):
    """
    See description of :class:`txtorcon.TCPHiddenServiceEndpoint`'s
    class-method ``global_tor``

    :param control_port:
        a TCP port upon which to run the launched Tor's
        control-protocol (selected by the OS by default).

    :param progress_updates:
        A callable that takes 3 args: ``percent, tag, message`` which
        is called when Tor announcing some progress setting itself up.

    :returns:
        a ``Deferred`` that fires a :class:`txtorcon.TorConfig` which is
        bootstrapped.

    The _tor_launcher keyword arg is internal-only.
    """
    global _global_tor_config
    global _global_tor_lock
    yield _global_tor_lock.acquire()

    try:
        if _global_tor_config is None:
            _global_tor_config = config = yield _create_default_config(reactor)

            # start Tor launching
            yield _tor_launcher(reactor, config, progress_updates)
            yield config.post_bootstrap

        else:
            cp = _global_tor_config.ControlPort
            if control_port is not None and control_port != cp:
                raise RuntimeError(
                    "ControlPort is %s, you wanted %s" % (cp, control_port))

        defer.returnValue(_global_tor_config)
    finally:
        _global_tor_lock.release()


@defer.inlineCallbacks
def _create_default_config(reactor, control_port=None):
    """
    Internal method to create a new TorConfig instance with defaults.
    """
    config = TorConfig()
    if control_port is None:
        control_port = yield available_tcp_port(reactor)
    config.ControlPort = control_port
    config.SOCKSPort = 0
    defer.returnValue(config)


class IProgressProvider(Interface):
    """FIXME move elsewhere? think harder?"""
    def add_progress_listener(listener):
        """
        Adds a progress listener. The listener is a callable that gets
        called with 3 arguments corresponding to Tor's updates:
        (percent, tag, message). percent is an integer from 0 to 100,
        tag and message are both strings. (message is the
        human-readable one)
        """


@implementer(IStreamServerEndpoint, IProgressProvider)
class TCPHiddenServiceEndpoint(object):
    """This represents something listening on an arbitrary local port
    that has a Tor configured with a Hidden Service pointing at
    it. :api:`twisted.internet.endpoints.TCP4ServerEndpoint
    <TCP4ServerEndpoint>` is used under the hood to do the local
    listening.

    There are three main ways to use this class, and you are
    encouraged to use the @classmethod ways of creating instances:
    `system_tor <#txtorcon.TCPHiddenServiceEndpoint.system_tor>`_,
    `global_tor <#txtorcon.TCPHiddenServiceEndpoint.global_tor>`_,
    and `private_tor <#txtorcon.TCPHiddenServiceEndpoint.private_tor>`_

    1. system_tor(...) connects to an already-started tor on the
       endpoint you specify; stricly speaking not a "system" tor since
       you could have spawned it some other way. See `Tor bug 11291
       <https://trac.torproject.org/projects/tor/ticket/11291>`_
       however.

    2. global_tor(...) refers to a single possible Tor instance
       per python process. So the first call to this launches a new Tor, and
       subsequent calls re-use the existing Tor (that is, add more hidden
       services to it).

    3. private_tor(...) launches a new Tor instance no matter what, so
       it will have just the one hidden serivce on it.

    If you need to set configuration options that are not reflected in
    any of the method signatures above, you'll have to construct an
    instance of this class yourself (i.e. with a TorConfig instance
    you've created).

    No matter how you came by your instance, calling `listen()` on it
    causes Tor to be launched or connected-to, your hidden service to
    be added, checks that the descriptor is uploaded and you get a
    ``Deferred`` with an ``IListeningPort`` whose ``getHost()`` will
    return a :class:`txtorcon.TorOnionAddress`. The port object will
    also implement :class:`txtorcon.IHiddenService` so you can get the
    locally-listening address and hidden serivce directory::

        endpoint = ...
        port = yield endpoint.listen(...)
        uri = port.getHost().onion_uri
        port = port.getHost().onion_port
        addr = IHiddenService(port).local_address
        hsdir = IHiddenService(port).hidden_service_dir

    returns (via Deferred) an object that implements
    :api:`twisted.internet.interfaces.IStreamServerEndpoint`

    :ivar onion_uri: the public key, like ``timaq4ygg2iegci7.onion``
        which came from the hidden_service_dir's ``hostname`` file

    :ivar onion_private_key: the contents of ``hidden_service_dir/private_key``


    :ivar hiddenServiceDir: the data directory, either passed in or created
        with ``tempfile.mkstemp``

    """

    @classmethod
    def system_tor(cls, reactor, control_endpoint, public_port,
                   hidden_service_dir=None, local_port=None):
        """
        This returns a TCPHiddenServiceEndpoint connected to the
        endpoint you specify in `control_endpoint`. After connecting, a
        single hidden service is added. The endpoint can be a Unix
        socket if Tor's `ControlSocket` option was used (instead of
        `ControlPort`).

        .. note::

            If Tor bug #11291 is not yet fixed, this won't work if you
            only have Group access. XXX FIXME re-test
        """

        @defer.inlineCallbacks
        def _connect():
            tor_protocol = yield build_tor_connection(control_endpoint,
                                                      build_state=False)
            config = TorConfig(tor_protocol)
            yield config.post_bootstrap
            defer.returnValue(config)
        return TCPHiddenServiceEndpoint(reactor, _connect(), public_port,
                                        hidden_service_dir=hidden_service_dir,
                                        local_port=local_port)

    @classmethod
    def global_tor(cls, reactor, public_port, hidden_service_dir=None,
                   local_port=None, control_port=None, stealth_auth=None):
        """
        This returns a TCPHiddenServiceEndpoint connected to a
        txtorcon global Tor instance. The first time you call this, a
        new Tor will be launched. Subsequent calls will re-use the
        same connection (in fact, the very same TorControlProtocol and
        TorConfig instances). If the options you pass are incompatible
        with an already-launched Tor, RuntimeError will be thrown.

        It's probably best to not specify any option besides
        `public_port`, `hidden_service_dir`, and maybe `local_port`
        unless you have a specific need to.

        You can also access this global txtorcon instance via
        :method:`txtorcon.get_global_tor` (which is precisely what
        this method uses to get it).

        All keyword options have defaults (e.g. random ports, or
        tempdirs).

        :param stealth_auth:
            None, or a list of strings -- one for each stealth
            authenticator you require.
        """

        def progress(*args):
            progress.target(*args)
        config = get_global_tor(
            reactor,
            control_port=control_port,
            progress_updates=progress
        )
        # config is a Deferred here, but endpoint resolves it in
        # the listen() call
        r = TCPHiddenServiceEndpoint(
            reactor, config, public_port,
            hidden_service_dir=hidden_service_dir,
            local_port=local_port,
            stealth_auth=stealth_auth,
        )
        progress.target = r._tor_progress_update
        return r

    @classmethod
    def private_tor(cls, reactor, public_port,
                    hidden_service_dir=None, local_port=None,
                    control_port=None):
        """
        This returns a TCPHiddenServiceEndpoint that's always
        connected to its own freshly-launched Tor instance. All
        keyword options have defaults (e.g. random ports, or
        tempdirs).
        """

        def progress(*args):
            progress.target(*args)

        @defer.inlineCallbacks
        def _launch(control_port):
            config = yield _create_default_config(reactor, control_port)
            yield launch_tor(config, reactor, progress_updates=progress)
            yield config.post_bootstrap
            defer.returnValue(config)
        r = TCPHiddenServiceEndpoint(reactor, _launch(control_port),
                                     public_port,
                                     hidden_service_dir=hidden_service_dir,
                                     local_port=local_port)
        progress.target = r._tor_progress_update
        return r

    def __init__(self, reactor, config, public_port,
                 hidden_service_dir=None, local_port=None,
                 stealth_auth=None):
        """
        :param reactor:
            :api:`twisted.internet.interfaces.IReactorTCP` provider

        :param config:
            :class:`txtorcon.TorConfig` instance (doesn't need to be
            bootstrapped) or a Deferred. Note that ``save()`` will be
            called on this at least once. FIXME should I just accept a
            TorControlProtocol instance instead, and create my own
            TorConfig?

        :param public_port:
            The port number we will advertise in the hidden serivces
            directory.

        :param local_port:
            The port number we will perform our local tcp listen on and
            receive incoming connections from the tor process.

        :param hidden_service_dir:
            If not None, point to a HiddenServiceDir directory
            (i.e. with "hostname" and "private_key" files in it). If
            not provided, one is created with temp.mkstemp() AND
            DELETED when the reactor shuts down.

        :param stealth_auth:
            A list of strings, one name for each stealth authenticator
            you want. Like: ``['alice', 'bob']``

        :param endpoint_generator:
            A callable that generates a new instance of something that
            implements IServerEndpoint (by default TCP4ServerEndpoint)
        """

        self.reactor = reactor
        self.config = defer.maybeDeferred(lambda: config)
        self.public_port = public_port
        self.local_port = local_port
        self.stealth_auth = stealth_auth

        self.hidden_service_dir = hidden_service_dir
        self.tcp_listening_port = None
        self.hiddenservice = None
        self.retries = 0

        '''for IProgressProvider to add_progress_listener'''
        self.progress_listeners = []

        if self.hidden_service_dir is None:
            self.hidden_service_dir = tempfile.mkdtemp(prefix='tortmp')
            log.msg('Will delete "%s" at shutdown.' % self.hidden_service_dir)
            delete = functools.partial(shutil.rmtree, self.hidden_service_dir)
            reactor.addSystemEventTrigger('before', 'shutdown', delete)

    @property
    def onion_uri(self):
        if self.hiddenservice is None:
            return None
        try:
            return self.hiddenservice.hostname
        except IOError:
            return None

    @property
    def onion_private_key(self):
        if self.hiddenservice is None:
            return None
        try:
            return self.hiddenservice.private_key
        except IOError:
            return None

    def add_progress_listener(self, listener):
        """IProgressProvider API"""
        self.progress_listeners.append(listener)

    def _tor_progress_update(self, prog, tag, summary):
        log.msg('%d%% %s' % (prog, summary))
        for p in self.progress_listeners:
            p(prog, tag, summary)

    @defer.inlineCallbacks
    def listen(self, protocolfactory):
        """Implement :api:`twisted.internet.interfaces.IStreamServerEndpoint
        <IStreamServerEndpoint>`.

        Returns a Deferred that delivers an
        :api:`twisted.internet.interfaces.IListeningPort` implementation.

        This port can also be adapted to two other interfaces:

        :class:`txtorcon.IHiddenService` so you can get the
        `onion_uri` and `onion_private_key` members (these correspond
        to "hostname" and "private_key" from the HiddenServiceDir Tor
        is using).

        :class:`txtorcon.IProgressProvider` can provide you progress
        updates while Tor is launched. Note that Tor is not always
        launched when calling this listen() method.

        At this point, Tor will have fully started up and successfully
        accepted the hidden service's config.

        FIXME TODO: also listen for an INFO-level Tor message (does
        exist, #tor-dev says) that indicates the hidden service's
        descriptor is published.

        It is "connection_dir_client_reached_eof(): Uploaded
        rendezvous descriptor (status 200 ("Service descriptor (v2)
        stored"))" at INFO level.

        """

        self.protocolfactory = protocolfactory

        # self.config is always a Deferred; see __init__
        self.config = yield self.config
        # just to be sure:
        yield self.config.post_bootstrap

        # XXX - perhaps allow the user to pass in an endpoint
        # descriptor and make this one the default? Then would
        # probably want to check for "is a local interface or not" and
        # at *least* warn if it's not local...
        self.tcp_endpoint = serverFromString(self.reactor,
                                             'tcp:0:interface=127.0.0.1')
        d = self.tcp_endpoint.listen(self.protocolfactory)
        self.tcp_listening_port = yield d
        self.local_port = self.tcp_listening_port.getHost().port

        # NOTE at some point, we can support unix sockets here
        # once Tor does. See bug #XXX

        # specifically NOT creating the hidden-service dir; letting
        # Tor do it will more-likely result in a usable situation...
        if not os.path.exists(self.hidden_service_dir):
            log.msg(
                'Noting that "%s" does not exist; letting Tor create it.' %
                self.hidden_service_dir
            )

        # listen for the descriptor upload event
        info_callback = defer.Deferred()

        def info_event(msg):
            # XXX giant hack here; Right Thing would be to implement a
            # "real" event in Tor and listen for that.
            if 'Service descriptor (v2) stored' in msg:
                info_callback.callback(None)
        self.config.protocol.add_event_listener('INFO', info_event)

        hs_dirs = [hs.dir for hs in self.config.HiddenServices]
        if self.hidden_service_dir not in hs_dirs:
            authlines = []
            if self.stealth_auth:
                # like "stealth name0,name1"
                authlines = ['stealth ' + ','.join(self.stealth_auth)]
            self.hiddenservice = HiddenService(
                self.config, self.hidden_service_dir,
                ['%d 127.0.0.1:%d' % (self.public_port, self.local_port)],
                group_readable=1, auth=authlines,
            )
            self.config.HiddenServices.append(self.hiddenservice)
        yield self.config.save()

        self._tor_progress_update(100.0, 'wait_descriptor',
                                  'Waiting for descriptor upload...')
        yield info_callback  # awaits an INFO log-line from Tor .. sketchy
        yield self.config.protocol.remove_event_listener('INFO', info_event)
        self._tor_progress_update(100.0, 'wait_descriptor',
                                  'At least one descriptor uploaded.')

        # FIXME XXX need to work out what happens here on stealth-auth'd
        # things. maybe we need a separate StealthHiddenService
        # vs. HiddenService ?!
        # XXX that is, self.onion_uri isn't always avaialble :/

        uri = None
        if self.hiddenservice is not None:
            log.msg('Started hidden service port %d' % self.public_port)
            for client in self.hiddenservice.clients:
                # XXX FIXME just taking the first one on multi-client services
                if uri is None:
                    uri = client[1]
                log.msg('  listening on %s.onion' % client[1])

        defer.returnValue(
            TorOnionListeningPort(
                self.tcp_listening_port,
                self.hidden_service_dir,
                uri,
                self.public_port,
                self.config,
            )
        )


@implementer(IAddress)
class TorOnionAddress(FancyEqMixin, object):
    """
    A ``TorOnionAddress`` represents the public address of a Tor hidden
    service.

    :ivar type: A string describing the type of transport, 'onion'.

    :ivar onion_uri: The public-key onion address (e.g. timaq4ygg2iegci7.onion)

    :ivar onion_port: The port we're advertising inside the Tor network.

    In otherwords, we should be reachable at (onion_uri, onion_port)
    via Tor.
    """
    compareAttributes = ('type', 'onion_uri', 'onion_port')
    type = 'onion'

    def __init__(self, uri, port):
        self.onion_uri = uri
        self.onion_port = port

    def __repr__(self):
        return '%s(%r, %d)' % (
            self.__class__.__name__, self.onion_uri, self.onion_port)

    def __hash__(self):
        return hash((self.type, self.onion_uri, self.onion_port))


class IHiddenService(Interface):
    local_address = Attribute(
        'The actual machine address we are listening on.')
    hidden_service_dir = Attribute(
        'The hidden service directory, where "hostname" and "private_key" '
        'files live.')
    tor_config = Attribute(
        'The TorConfig object attached to the Tor hosting this hidden service '
        '(in turn has .protocol for TorControlProtocol).')


@implementer(IListeningPort, IHiddenService)
class TorOnionListeningPort(object):
    """
    Our TCPHiddenServiceEndpoint's `listen` method will return a deferred
    which fires an instance of this object.
    The `getHost` method will return a TorOnionAddress instance... which
    can be used to determine the onion address of a newly created Tor Hidden
    Service.

    `startListening` and `stopListening` methods proxy to the "TCP
    ListeningPort" object...
    which implements IListeningPort interface but has many more
    responsibilities we needn't worry about here.
    """

    def __init__(self, listening_port, hs_dir, uri, port, tor_config):
        self.local_address = listening_port
        self.hidden_service_dir = hs_dir
        self._config_ref = weakref.ref(tor_config)
        self.address = TorOnionAddress(uri, port)

    def startListening(self):
        """IListeningPort API"""
        self.local_address.startListening()

    def stopListening(self):
        """IListeningPort API"""
        self.local_address.stopListening()

    def getHost(self):
        """IListeningPort API"""
        return self.address

    def __str__(self):
        return '<TorOnionListeningPort %s:%d>' % (self.address.onion_uri,
                                                  self.address.onion_port)

    # local_address IHiddenService API fulfilled in ctor
    # hidden_service_dir IHiddenService API fulfilled in ctor
    @property
    def tor_config(self):
        return self._config_ref()  # None if ref dead


@implementer(IStreamServerEndpointStringParser, IPlugin)
class TCPHiddenServiceEndpointParser(object):
    """
    This provides a twisted IPlugin and
    IStreamServerEndpointsStringParser so you can call
    :api:`twisted.internet.endpoints.serverFromString
    <serverFromString>` with a string argument like:

    ``onion:80:localPort=9876:controlPort=9052:hiddenServiceDir=/dev/shm/foo``

    ...or simply:

    ``onion:80``

    If ``controlPort`` is specified, it means connect to an already-running Tor
    on that port and add a hidden-serivce to it.

    ``localPort`` is optional and if not specified, a port is selected by
    the OS.

    If ``hiddenServiceDir`` is not specified, one is created with
    ``tempfile.mkstemp()``. The IStreamServerEndpoint returned will be
    an instance of :class:`txtorcon.TCPHiddenServiceEndpoint`
    """
    prefix = "onion"

    # note that these are all camelCase because Twisted uses them to
    # do magic parsing stuff, and to conform to Twisted's conventions
    # we should use camelCase in the endpoint definitions...
    def parseStreamServer(self, reactor, public_port, localPort=None,
                          controlPort=None, hiddenServiceDir=None):
        '''
        :api:`twisted.internet.interfaces.IStreamServerEndpointStringParser`
        '''

        public_port = int(public_port)

        if localPort is not None:
            localPort = int(localPort)

        hsd = hiddenServiceDir
        if hsd:
            orig = hsd
            hsd = os.path.expanduser(hsd)
            hsd = os.path.realpath(hsd)
            if orig != hsd:
                log.msg('Using "%s" for hsd' % hsd)

        if controlPort:
            try:
                ep = clientFromString(
                    reactor, "tcp:host=127.0.0.1:port=%d" % int(controlPort))
            except ValueError:
                ep = clientFromString(reactor, "unix:path=%s" % controlPort)
            return TCPHiddenServiceEndpoint.system_tor(reactor, ep,
                                                       public_port,
                                                       hidden_service_dir=hsd,
                                                       local_port=localPort)

        return TCPHiddenServiceEndpoint.global_tor(reactor, public_port,
                                                   hidden_service_dir=hsd,
                                                   local_port=localPort,
                                                   control_port=controlPort)


@implementer(IStreamClientEndpoint)
class TorClientEndpoint(object):
    """
    I am an endpoint class who attempts to establish a SOCKS5
    connection with the system tor process. If no socks_endpoint is
    given, I will try TCP4 to localhost on ports 9050 then 9150.

    :param socks_endpoint:
        An IStreamClientEndpoint that will connect to a SOCKS5
        port. Tor can speak SOCKS5 over either TCP4 or Unix sockets.

    :param tls:
        If True, we will attemp TLS negotiation after the SOCKS forwarding
        is set up.
    """
    # XXX should get these via the control connection, i.e. ask Tor
    # via GETINFO net/listeners/socks or whatever
    socks_ports_to_try = [9050, 9150]

    def __init__(self, host, port,
                 socks_endpoint=None,
                 socks_username=None, socks_password=None,
                 tls=False, **kw):
        if host is None or port is None:
            raise ValueError('host and port must be specified')

        self.host = host
        self.port = int(port)
        self.socks_endpoint = socks_endpoint
        self.socks_username = socks_username
        self.socks_password = socks_password
        self.tls = tls

        if self.tls and not _HAVE_TLS:
            raise ValueError(
                "'tls=True' but we don't have TLS support"
            )

        # backwards-compatibility: you used to specify a TCP SOCKS
        # endpoint via socks_hostname= and socks_port= kwargs
        if self.socks_endpoint is None:
            try:
                self.socks_endpoint = TCP4ClientEndpoint(
                    reactor,
                    kw['socks_hostname'],
                    kw['socks_port'],
                )
                # XXX should deprecation-warn here
            except KeyError:
                pass

        # this is a separate "if" from above in case socks_endpoint
        # was None but the user specified the (old)
        # socks_hostname/socks_port (in which case we do NOT want
        # guessing_enabled
        if self.socks_endpoint is None:
            self._socks_port_iter = iter(self.socks_ports_to_try)
            self._socks_guessing_enabled = True
        else:
            self._socks_guessing_enabled = False

    @defer.inlineCallbacks
    def connect(self, protocolfactory):
        last_error = None
        kwargs = dict()
        if self.socks_username is not None and self.socks_password is not None:
            kwargs['methods'] = dict(
                login=(self.socks_username, self.socks_password),
            )
        if self.socks_endpoint is not None:
            args = (self.host, self.port, self.socks_endpoint)
            socks_ep = SOCKS5ClientEndpoint(*args, **kwargs)
            if self.tls:
                context = optionsForClientTLS(unicode(self.host))
                socks_ep = TLSWrapClientEndpoint(context, socks_ep)
            proto = yield socks_ep.connect(protocolfactory)
            defer.returnValue(proto)
        else:
            for socks_port in self._socks_port_iter:
                tor_ep = TCP4ClientEndpoint(
                    reactor,
                    "127.0.0.1",
                    socks_port,
                )
                args = (self.host, self.port, tor_ep)
                socks_ep = SOCKS5ClientEndpoint(*args, **kwargs)
                if self.tls:
                    # XXX only twisted 14+
                    context = optionsForClientTLS(unicode(self.host))
                    socks_ep = TLSWrapClientEndpoint(context, socks_ep)

                try:
                    proto = yield socks_ep.connect(protocolfactory)
                    defer.returnValue(proto)

                except error.ConnectError as e0:
                    last_error = e0
            if last_error is not None:
                raise last_error


@implementer(IPlugin, IStreamClientEndpointStringParserWithReactor)
class TorClientEndpointStringParser(object):
    """
    This provides a twisted IPlugin and
    IStreamClientEndpointsStringParser so you can call
    :api:`twisted.internet.endpoints.clientFromString
    <clientFromString>` with a string argument like:

    ``tor:host=timaq4ygg2iegci7.onion:port=80:socksPort=9050``

    ...or simply:

    ``tor:host=timaq4ygg2iegci7.onion:port=80``

    You may also include a username + password. By default, Tor will
    not put two streams that provided different authentication on the
    same circuit.

    ``tor:host=torproject.org:port=443:socksUsername=foo:socksPassword=bar``

    If ``socksPort`` is specified, it means only use that port to
    attempt to proxy through Tor. If unspecified then try some likely
    socksPorts such as [9050, 9150].

    NOTE that I'm using camelCase variable names in the endpoint
    string to be consistent with the rest of Twisted's naming (and
    their endpoint parsers).

    XXX FIXME if there is no Tor instance found at socksPort, we
    should launch one. Perhaps a separate option? (Should be on by
    default, though, I think).
    """
    prefix = "tor"

    def _parseClient(self, host=None, port=None,
                     socksHostname=None, socksPort=None,
                     socksUsername=None, socksPassword=None):
        if port is not None:
            port = int(port)
        if socksHostname is None:
            socksHostname = '127.0.0.1'
        if socksPort is not None:
            socksPort = int(socksPort)

        ep = None
        if socksPort is not None:
            ep = TCP4ClientEndpoint(reactor, socksHostname, socksPort)
        return TorClientEndpoint(
            host, port,
            socks_endpoint=ep,
            socks_username=socksUsername,
            socks_password=socksPassword,
        )

    def parseStreamClient(self, *args, **kwargs):
        # for Twisted 14 and 15 (and more) the first argument is
        # 'reactor', for older Twisteds it's not
        if _HAVE_TX_14:
            return self._parseClient(*args[1:], **kwargs)
        return self._parseClient(*args, **kwargs)
