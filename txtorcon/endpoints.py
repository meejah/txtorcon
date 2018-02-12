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
from txtorcon.socks import TorSocksEndpoint

from twisted.internet.interfaces import IStreamClientEndpointStringParserWithReactor
from twisted.internet import defer, error
from twisted.python import log
from twisted.internet.interfaces import IStreamServerEndpointStringParser
from twisted.internet.interfaces import IStreamServerEndpoint
from twisted.internet.interfaces import IStreamClientEndpoint
from twisted.internet.interfaces import IListeningPort
from twisted.internet.interfaces import IAddress
from twisted.internet.endpoints import serverFromString
from twisted.internet.endpoints import clientFromString
from twisted.internet.endpoints import TCP4ClientEndpoint
# from twisted.internet.endpoints import UNIXClientEndpoint
# from twisted.internet import error
from twisted.plugin import IPlugin
from twisted.python.util import FancyEqMixin

from zope.interface import implementer
from zope.interface import Interface, Attribute

from .torconfig import TorConfig, launch_tor, HiddenService
from .torconfig import _endpoint_from_socksport_line
from .util import SingleObserver


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
        with ``tempfile.mkdtemp``

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

        from txtorcon.controller import connect
        tor = connect(reactor, control_endpoint)
        tor.addCallback(lambda t: t.get_config())
        # tor is a Deferred
        return TCPHiddenServiceEndpoint(reactor, tor, public_port,
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
        :meth:`txtorcon.get_global_tor` (which is precisely what
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
            :class:`txtorcon.TorConfig` instance.

        :param public_port:
            The port number we will advertise in the hidden serivces
            directory.

        :param local_port:
            The port number we will perform our local tcp listen on and
            receive incoming connections from the tor process.

        :param hidden_service_dir:
            If not None, point to a HiddenServiceDir directory
            (i.e. with "hostname" and "private_key" files in it). If
            not provided, one is created with temp.mkdtemp() AND
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
            self.reactor.addSystemEventTrigger('before', 'shutdown', delete)

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
        # we re-adjust the percentage-scale, using 105% and 110% for
        # the two parts of waiting for descriptor upload. That is, we
        # want: 110 * constant == 100.0
        for p in self.progress_listeners:
            p(prog * (100.0 / 110.0), tag, summary)

    @defer.inlineCallbacks
    def listen(self, protocolfactory):
        """
        Implement :api:`twisted.internet.interfaces.IStreamServerEndpoint
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
    ``tempfile.mkdtemp()``. The IStreamServerEndpoint returned will be
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


@defer.inlineCallbacks
def _create_socks_endpoint(reactor, control_protocol, socks_config=None):
    """
    Internal helper.

    This uses an already-configured SOCKS endpoint from the attached
    Tor, or creates a new TCP one (and configures Tor with it). If
    socks_config is non-None, it is a SOCKSPort line and will either
    be used if it already exists or will be created.
    """
    socks_ports = yield control_protocol.get_conf('SOCKSPort')
    if socks_ports:
        socks_ports = list(socks_ports.values())[0]
        if not isinstance(socks_ports, list):
            socks_ports = [socks_ports]
    else:
        # return from get_conf was an empty dict; we want a list
        socks_ports = []

    # everything in the SocksPort list can include "options" after the
    # initial value. We don't care about those, but do need to strip
    # them.
    socks_ports = [port.split()[0] for port in socks_ports]

    # could check platform? but why would you have unix ports on a
    # platform that doesn't?
    unix_ports = set([p.startswith('unix:') for p in socks_ports])
    tcp_ports = set(socks_ports) - unix_ports

    socks_endpoint = None
    for p in list(unix_ports) + list(tcp_ports):  # prefer unix-ports
        if socks_config and p != socks_config:
            continue
        try:
            socks_endpoint = _endpoint_from_socksport_line(reactor, p)
        except Exception as e:
            log.msg("clientFromString('{}') failed: {}".format(p, e))

    # if we still don't have an endpoint, nothing worked (or there
    # were no SOCKSPort lines at all) so we add config to tor
    if socks_endpoint is None:
        if socks_config is None:
            # is a unix-socket in /tmp on a supported platform better than
            # this?
            port = yield available_tcp_port(reactor)
            socks_config = str(port)
        socks_ports.append(socks_config)

        # NOTE! We must set all the ports in one command or we'll
        # destroy pre-existing config
        args = []
        for p in socks_ports:
            args.append('SOCKSPort')
            args.append(p)
        yield control_protocol.set_conf(*args)
        socks_endpoint = _endpoint_from_socksport_line(reactor, socks_config)

    assert socks_endpoint is not None
    defer.returnValue(socks_endpoint)


@implementer(IStreamClientEndpoint)
class TorClientEndpoint(object):
    """
    An IStreamClientEndpoint which establishes a connection via Tor.

    You should not instantiate these directly; use
    ``clientFromString()``, :meth:`txtorcon.Tor.stream_via` or
    :meth:`txtorcon.Circuit.stream_via`

    :param host:
        The hostname to connect to. This of course can be a Tor Hidden
        Service onion address.

    :param port: The tcp port or Tor Hidden Service port.

    :param socks_endpoint: An IStreamClientEndpoint pointing at (one
        of) our Tor's SOCKS ports. These can be instantiated with
        :meth:`txtorcon.TorConfig.socks_endpoint`.

    :param tls: Can be False or True (to get default Browser-like
        hostname verification) or the result of calling
        optionsForClientTLS() yourself. Default is True.
    """

    socks_ports_to_try = [9050, 9150]

    @classmethod
    def from_connection(cls, reactor, control_protocol, host, port,
                        tls=None,
                        socks_endpoint=None):
        if socks_endpoint is None:
            socks_endpoint = _create_socks_endpoint(reactor, control_protocol)
        return TorClientEndpoint(
            host, port,
            socks_endpoint=socks_endpoint,
            tls=tls,
            reactor=reactor,
        )

    def __init__(self,
                 host, port,
                 socks_endpoint=None,  # can be Deferred
                 tls=False,

                 # XXX our custom SOCKS stuff doesn't support auth (yet?)
                 socks_username=None, socks_password=None,
                 reactor=None, **kw):
        if host is None or port is None:
            raise ValueError('host and port must be specified')

        self.host = host
        self.port = int(port)
        self._socks_endpoint = socks_endpoint
        self._socks_username = socks_username
        self._socks_password = socks_password
        self._tls = tls
        # XXX FIXME we 'should' probably include 'reactor' as the
        # first arg to this class, but technically that's a
        # breaking change :(
        self._reactor = reactor
        if reactor is None:
            from twisted.internet import reactor
            self._reactor = reactor

        # backwards-compatibility: you used to specify a TCP SOCKS
        # endpoint via socks_host= and socks_port= kwargs
        if self._socks_endpoint is None:
            try:
                self._socks_endpoint = TCP4ClientEndpoint(
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
        if self._socks_endpoint is None:
            self._socks_guessing_enabled = True
        else:
            self._socks_guessing_enabled = False

        # XXX think, do we want to expose these like this? Or some
        # other way (because they're for stream-isolation, not actual
        # auth)
        self._socks_username = socks_username
        self._socks_password = socks_password
        self._when_address = SingleObserver()

    def _get_address(self):
        """
        internal helper.

        *le sigh*. This is basically just to support
        TorCircuitEndpoint; see TorSocksEndpoint._get_address(). There
        shouldn't be any need for "actual users" to need this!

        This returns a Deferred that fires once:
          - we have an underlying SOCKS5 endpoint
          - ...and it has received a local connection (and hence the address/port)
        """
        return self._when_address.when_fired()

    @defer.inlineCallbacks
    def connect(self, protocolfactory):
        last_error = None
        # XXX fix in socks.py stuff for socks_username, socks_password
        if self._socks_username or self._socks_password:
            raise RuntimeError(
                "txtorcon socks support doesn't yet do username/password"
            )
        if self._socks_endpoint is not None:
            socks_ep = TorSocksEndpoint(
                self._socks_endpoint,
                self.host, self.port,
                self._tls,
            )
            # forward the address to any listeners we have
            socks_ep._get_address().addCallback(self._when_address.fire)
            proto = yield socks_ep.connect(protocolfactory)
            defer.returnValue(proto)
        else:
            for socks_port in self.socks_ports_to_try:
                tor_ep = TCP4ClientEndpoint(
                    self._reactor,
                    "127.0.0.1",  # XXX socks_hostname, no?
                    socks_port,
                )
                socks_ep = TorSocksEndpoint(tor_ep, self.host, self.port, self._tls)
                # forward the address to any listeners we have
                socks_ep._get_address().addCallback(self._when_address.fire)
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
    attempt to proxy through Tor. If unspecified, we ... XXX?

    NOTE that I'm using camelCase variable names in the endpoint
    string to be consistent with the rest of Twisted's naming (and
    their endpoint parsers).

    XXX FIXME if there is no Tor instance found at socksPort, we
    should launch one. Perhaps a separate option? (Should be on by
    default, though, I think).
    """
    prefix = "tor"

    def _parseClient(self, reactor,
                     host=None, port=None,
                     socksHostname=None, socksPort=None,
                     socksUsername=None, socksPassword=None):
        if port is not None:
            port = int(port)

        ep = None
        if socksPort is not None:
            # Tor can speak SOCKS over unix, too, but this doesn't let
            # us pass one ...
            ep = TCP4ClientEndpoint(reactor, socksHostname, int(socksPort))
        return TorClientEndpoint(
            host, port,
            socks_endpoint=ep,
            socks_username=socksUsername,
            socks_password=socksPassword,
        )

    def parseStreamClient(self, *args, **kwargs):
        # for Twisted 14 and 15 (and more) the first argument is
        # 'reactor', for older Twisteds it's not
        return self._parseClient(*args, **kwargs)
