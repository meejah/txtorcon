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

# backwards-compatibility dance: we "should" be using the
# ...WithReactor class, but in Twisted prior to 14, there is no such
# class (and the parse() doesn't provide a 'reactor' argument).
try:
    from twisted.internet.interfaces import IStreamClientEndpointStringParserWithReactor
    _HAVE_TX_14 = True
except ImportError:
    from twisted.internet.interfaces import IStreamClientEndpointStringParser as IStreamClientEndpointStringParserWithReactor
    _HAVE_TX_14 = False

from twisted.internet import defer
from twisted.python import log
from twisted.internet.interfaces import IStreamServerEndpointStringParser
from twisted.internet.interfaces import IStreamServerEndpoint
from twisted.internet.interfaces import IStreamClientEndpoint
from twisted.internet.interfaces import IListeningPort
from twisted.internet.interfaces import IAddress
from twisted.internet.endpoints import serverFromString
from twisted.internet.endpoints import clientFromString
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.endpoints import UNIXClientEndpoint
from twisted.internet import error
from twisted.plugin import IPlugin
from twisted.python.util import FancyEqMixin

from zope.interface import implementer
from zope.interface import Interface, Attribute

from .onion import FilesystemHiddenService, EphemeralHiddenService
from .torconfig import TorConfig
from .torstate import build_tor_connection


_global_tor = None  # instance of txtorcon.controller.Tor
_global_tor_lock = defer.DeferredLock()
# we need the lock because we (potentially) yield several times while
# "creating" the TorConfig instance


@defer.inlineCallbacks
def get_global_tor(reactor, control_port=None,
                   progress_updates=None,
                   _tor_launcher=None):
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

    # XXX need to fuxor around to unify this with controller.tor stuff
    global _global_tor
    global _global_tor_lock
    yield _global_tor_lock.acquire()

    if _tor_launcher is None:
        # XXX :( mutual dependencies...really get_global_tor should be
        # in controller.py if it's going to return a Tor instance.
        from .controller import launch
        _tor_launcher = launch

    try:
        if _global_tor is None:
            _global_tor = yield _tor_launcher(reactor, progress_updates=progress_updates)

        else:
            try:
                already_port = _global_tor.config.ControlPort
                if control_port is not None and control_port != already_port:
                    raise RuntimeError(
                        "ControlPort is already '{}', but you wanted '{}'",
                        already_port,
                        control_port,
                    )
            except KeyError:
                # XXX i think just from tests?
                print("No ControlPort -- weird, but we'll let it go")
                
        defer.returnValue(_global_tor)
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


# XXX essentially, we either want an ephemeral vs. non-ephemeral etc
# endpoint instance, *or* we just make this a "delayed" version of
# create_onion_service -- i.e. holds all the same args as that and
# listen() instantiates it and knows "which" tor it wants.
@implementer(IStreamServerEndpoint)
@implementer(IProgressProvider)
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
                   hidden_service_dir=None,
                   local_port=None,
                   ephemeral=None,
                   private_key=None):
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
        tor.addCallback(lambda t: t.config)
        # tor is a Deferred
        return TCPHiddenServiceEndpoint(
            reactor, tor, public_port,
            hidden_service_dir=hidden_service_dir,
            local_port=local_port,
            ephemeral=ephemeral,
            private_key=private_key,
        )

    @classmethod
    def global_tor(cls, reactor, public_port,
                   hidden_service_dir=None,
                   local_port=None,
                   control_port=None,
                   stealth_auth=None,
                   ephemeral=None,
                   private_key=None):
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
        tor = get_global_tor(
            reactor,
            control_port=control_port,
            progress_updates=progress
        )
        # tor is a Deferred here, but endpoint resolves it in
        # the listen() call
        r = TCPHiddenServiceEndpoint(
            reactor, tor, public_port,
            hidden_service_dir=hidden_service_dir,
            local_port=local_port,
            stealth_auth=stealth_auth,
            ephemeral=ephemeral,
            private_key=private_key,
        )
        progress.target = r._tor_progress_update
        return r

    @classmethod
    def private_tor(cls, reactor, public_port,
                    hidden_service_dir=None,
                    local_port=None,
                    control_port=None,
                    ephemeral=None,
                    private_key=None):
        """
        This returns a TCPHiddenServiceEndpoint that's always
        connected to its own freshly-launched Tor instance. All
        keyword options have defaults (e.g. random ports, or
        tempdirs).
        """

        def progress(*args):
            progress.target(*args)

        from .controller import launch
        # XXX no way to tell launch() what control-port endpoint to use!
        tor = launch(reactor, progress_updates=progress)
        r = TCPHiddenServiceEndpoint(
            reactor, tor, public_port,
            hidden_service_dir=hidden_service_dir,
            local_port=local_port,
            ephemeral=ephemeral,
            private_key=private_key,
        )
        progress.target = r._tor_progress_update
        return r

    @classmethod
    def create(
            cls, reactor, config, public_port,
            hidden_service_dir=None,
            local_port=None,
            control_port=None,
            ephemeral=None,
            private_key=None,
            progress=None):
        pass

    def __init__(self, reactor, config, public_port,
                 hidden_service_dir=None,
                 local_port=None,
                 stealth_auth=None,
                 ephemeral=None,  # will be set to True, unless hsdir spec'd
                 private_key=None):
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

        # this supports API backwards-compatibility -- if you didn't
        # explicitly specify ephemeral=True, but *did* set
        # hidden_service_dir
        if ephemeral is None:
            ephemeral = True
            if hidden_service_dir is not None:
                # XXX emit warning?
                ephemeral = False

        if stealth_auth and ephemeral:
            raise ValueError(
                "'ephemeral=True' onion services don't support stealth_auth"
            )

        if ephemeral and hidden_service_dir is not None:
            raise ValueError(
                "Specifying 'hidden_service_dir' is incompatible"
                " with 'ephemeral=True'"
            )

        self.reactor = reactor
        self._config = defer.maybeDeferred(lambda: config)
        self.public_port = public_port
        self.local_port = local_port
        self.stealth_auth = stealth_auth

        self.ephemeral = ephemeral
        self.private_key = private_key
        # XXX what if we're an ephemeral service?
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

        This port can also be adapted to
        :class:`txtorcon.IHiddenService` so you can get the
        `onion_uri` and `onion_private_key` members (these correspond
        to "hostname" and "private_key" from the HiddenServiceDir Tor
        is using).

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

        # XXX we only use .config from this, and the "old code" always
        # sent a TorConfig ... leave it like that? Otherwise *all*
        # endpoints then demand the "high-level API only" :/

        # _config is always a Deferred; see __init__
        self._config = yield self._config

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

        # XXX move to constructor? (because it's validation)
        if self.private_key is not None and not self.ephemeral:
            raise RuntimeError("'private_key' only understood for ephemeral services")

        # see note in _tor_progress_update; we extend the percent
        # range to 110% for the descriptor upload
        self._tor_progress_update(101.0, 'wait_descriptor',
                                  'uploading descriptor')

        # see if the hidden-serivce instance we want is already in the
        # config; for non-ephemeral services, the directory is unique;
        # for ephemeral services, the key should exist and be unique.
        hs_dirs = [hs.dir for hs in self._config.HiddenServices if hasattr(hs, 'dir')]
        if self.hidden_service_dir not in hs_dirs:
            authlines = []
            if self.stealth_auth:
                # like "stealth name0,name1"
                authlines = ['stealth ' + ','.join(self.stealth_auth)]
            if self.ephemeral:
                # this waits for descriptor upload .. so needs the progress stuff?
                self.hiddenservice = yield EphemeralHiddenService.create(
                    self._config,
                    ['%d 127.0.0.1:%d' % (self.public_port, self.local_port)],
                    private_key=self.private_key,
                    detach=False,
                    discard_key=False,
                    progress=self._tor_progress_update,
                )
            else:
                # XXX should be a .create() call
                # -> also, should wait for descriptor upload...
                self.hiddenservice = yield FilesystemHiddenService.create(
                    self._config,
                    self.hidden_service_dir,
                    ['%d 127.0.0.1:%d' % (self.public_port, self.local_port)],
                    auth=authlines,
                    progress=self._tor_progress_update,
                )
        else:
            for hs in self._config.HiddenServices:
                if hs.dir == self.hidden_service_dir:
                    self.hiddenservice = hs

        assert self.hiddenservice is not None, "internal error"

        self._tor_progress_update(110.0, 'wait_descriptor',
                                  'At least one descriptor uploaded')

        log.msg('Started hidden service on %s:%d' % (self.onion_uri, self.public_port))

        defer.returnValue(
            TorOnionListeningPort(
                self.tcp_listening_port,
                self.public_port,
                self.hiddenservice,
                self._config,
            )
        )


@implementer(IAddress)
class TorOnionAddress(FancyEqMixin, object):
    """
    A ``TorOnionAddress`` represents the public address of a Tor hidden
    service.

    :ivar type: A string describing the type of transport, 'onion'.

    :ivar port: The public port we're advertising

    :ivar clients: A list of IHiddenServiceClient instances, at least 1.
    """
    compareAttributes = ('type', 'onion_port', 'onion_key')
    type = 'onion'

    def __init__(self, port, hs):
        self.onion_port = port
        try:
            self.onion_uri = hs.hostname
        except IOError:
            self.onion_uri = None
        self._hiddenservice = hs

    @property
    def onion_key(self):
        return self._hiddenservice.private_key

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, self.onion_uri)

    def __hash__(self):
        return hash((self.type, self.onion_uri, self.onion_port))


class IHiddenService(Interface):
    local_address = Attribute(
        'The actual local machine address we are listening on.')
    public_port = Attribute("The port our service can be contacted on")
    tor_config = Attribute(
        'The TorConfig object attached to the Tor hosting this hidden service '
        '(in turn has .protocol for TorControlProtocol).')
    clients = Attribute(
        'List of IHiddenServiceClient instances.'
        'Unauthenticated services will have 0 clients.'
        'Basic-auth services will have 1 client, called "default".'
    )


class IHiddenServiceClient(Interface):
    name = Attribute('A descriptive name of this client; "default" for basic-auth services')
    onion_uri = Attribute('Derived from the public key, e.g. "timaq4ygg2iegci7.onion"')
    private_key = Attribute('Blob of bytes representing the private key for this service')


# XXX this stuff moves to torconfig?
# @implementer(IHiddenServiceClient)
# class HiddenServiceClient(object):
#     name = 'default'

#     def __init__(self, hidden_service_dir):
#         self.hidden_service_dir = hidden_service_dir
#         with open(join(self.hidden_service_dir, 'hostname'), 'r') as f:
#             self.onion_uri = f.read().strip()
#         with open(join(self.hidden_service_dir, 'private_key'), 'r') as f:
#             self.private_key = f.read().strip()


@implementer(IHiddenServiceClient)
class EphemeralHiddenServiceClient(object):
    name = 'default'

    def __init__(self, onion_uri, private_key):
        self.hostname = onion_uri
        self.private_key = private_key


# XXX should implement IOnionService
# ...so what shall implement IOnionClients etc? need multiple TorOnionListeningPort impls?
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

    def __init__(self, listening_port, public_port, hiddenservice, tor_config):
        self.local_address = listening_port
        self.public_port = public_port
        # XXX should this be a weakref too? is there circ-ref here?
        self._hiddenservice = hiddenservice
        # XXX why is this a weakref? circ-ref?
        self._config_ref = weakref.ref(tor_config)
        self._address = TorOnionAddress(public_port, hiddenservice)

    def startListening(self):
        """IListeningPort API"""
        self.local_address.startListening()

    def stopListening(self):
        """IListeningPort API"""
        self.local_address.stopListening()

    def getHost(self):
        """IListeningPort API"""
        return self._address

    def __str__(self):
        return '<TorOnionListeningPort %s:%d>' % (self._address.onion_uri, self._address.onion_port)

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
    
    # XXX need to be able to pass privateKey too (mutually exclusive with hiddenServiceDir)
    def parseStreamServer(self, reactor, public_port, localPort=None,
                          controlPort=None, hiddenServiceDir=None,
                          privateKey=None):
        """
        :api:`twisted.internet.interfaces.IStreamServerEndpointStringParser`
        """

        if hiddenServiceDir is not None and privateKey is not None:
            raise ValueError(
                "Only one of hiddenServiceDir and privateKey accepted"
            )

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
            return TCPHiddenServiceEndpoint.system_tor(
                reactor, ep, public_port,
                hidden_service_dir=hsd,
                private_key=privateKey,
                local_port=localPort,
                ephemeral=(hsd is None),
            )

        return TCPHiddenServiceEndpoint.global_tor(
            reactor, public_port,
            hidden_service_dir=hsd,
            private_key=privateKey,
            local_port=localPort,
            control_port=controlPort,
            ephemeral=(hsd is None),
        )


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
        optionsForClientTLS() yourself.

    :param _proxy_endpoint_generator: This is used for unit tests.
    """

    def __init__(self,
                 reactor,
                 host, port,
                 socks_endpoint,  # can be Deferred
                 tls=False,
                 got_source_port=None,

                 # XXX our custom SOCKS stuff doesn't support auth (yet?)
                 socks_username=None, socks_password=None):
        if host is None or port is None:
            raise ValueError('host and port must be specified')

        self.host = host
        self.port = int(port)
        self._tls = tls
        self._socks_endpoint = socks_endpoint
        self._reactor = reactor
        self._got_source_port = got_source_port

        # XXX think, do we want to expose these like this? Or some
        # other way (because they're for stream-isolation, not actual
        # auth)
        self._socks_username = socks_username
        self._socks_password = socks_password

    @defer.inlineCallbacks
    def connect(self, protocolfactory):
        tor_socks_ep = TorSocksEndpoint(
            self._socks_endpoint, self.host, self.port, self._tls, self._got_source_port,
        )

        proto = yield tor_socks_ep.connect(protocolfactory)
        defer.returnValue(proto)


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
                     socksUsername=None, socksPassword=None):
        if port is not None:
            port = int(port)

        return TorClientEndpoint(
            reactor,
            host, port,
            socks_endpoint=None,
            socks_username=socksUsername,
            socks_password=socksPassword
        )

    def parseStreamClient(self, *args, **kwargs):
        # for Twisted 14 and 15 (and more) the first argument is
        # 'reactor', for older Twisteds it's not
        if _HAVE_TX_14:
            return self._parseClient(*args, **kwargs)
        else:
            from twisted.internet import reactor
            return self._parseClient(reactor, *args, **kwargs)
