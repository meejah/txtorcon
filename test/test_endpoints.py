import os
import shutil
import tempfile

from mock import patch
from mock import Mock

from zope.interface import implements

from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.internet import defer, error, task, tcp
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet.endpoints import serverFromString
from twisted.internet.endpoints import clientFromString
from twisted.python.failure import Failure
from twisted.internet.interfaces import IReactorCore
from twisted.internet.interfaces import IProtocolFactory
from twisted.internet.interfaces import IProtocol
from twisted.internet.interfaces import IReactorTCP
from twisted.internet.interfaces import IListeningPort
from twisted.internet.interfaces import IAddress

from txtorcon import TorControlProtocol
from txtorcon import ITorControlProtocol
from txtorcon import TorConfig
from txtorcon import launch_tor
from txtorcon import TCPHiddenServiceEndpoint
from txtorcon import TorNotFound
from txtorcon import TCPHiddenServiceEndpointParser
from txtorcon import IProgressProvider
from txtorcon import TorOnionAddress
from txtorcon.util import NoOpProtocolFactory
from txtorcon.endpoints import get_global_tor                       # FIXME

import util


class EndpointTests(unittest.TestCase):

    def setUp(self):
        from txtorcon import endpoints
        endpoints._global_tor_config = None
        del endpoints._global_tor_lock
        endpoints._global_tor_lock = defer.DeferredLock()
        self.reactor = FakeReactorTcp(self)
        self.protocol = FakeControlProtocol([])
        self.config = TorConfig(self.protocol)
        self.protocol.answers.append('config/names=\nHiddenServiceOptions Virtual')
        self.protocol.answers.append('HiddenServiceOptions')
        self.patcher = patch('txtorcon.torconfig.find_tor_binary', return_value='/not/tor')
        self.patcher.start()

    def tearDown(self):
        from txtorcon import endpoints
        endpoints._global_tor_config = None
        del endpoints._global_tor_lock
        endpoints._global_tor_lock = defer.DeferredLock()
        self.patcher.stop()

    @defer.inlineCallbacks
    def test_global_tor(self):
        config = yield get_global_tor(Mock(), _tor_launcher=lambda x, y, z: True)
        self.assertEqual(0, config.SOCKSPort)

    @defer.inlineCallbacks
    def test_global_tor_error(self):
        config0 = yield get_global_tor(Mock(), _tor_launcher=lambda x, y, z: True)
        # now if we specify a control_port it should be an error since
        # the above should have launched one.
        try:
            config1 = yield get_global_tor(Mock(), control_port=111,
                                           _tor_launcher=lambda x, y, z: True)
            self.fail()
        except RuntimeError as e:
            # should be an error
            pass

    @defer.inlineCallbacks
    def test_endpoint_properties(self):
        ep = yield TCPHiddenServiceEndpoint.private_tor(Mock(), 80)
        self.assertEqual(None, ep.onion_private_key)
        self.assertEqual(None, ep.onion_uri)
        ep.hiddenservice = Mock()
        ep.hiddenservice.private_key = 'mumble'
        self.assertEqual('mumble', ep.onion_private_key)

    @defer.inlineCallbacks
    def test_private_tor(self):
        m = Mock()
        from txtorcon import endpoints
        endpoints.launch_tor = m
        ep = yield TCPHiddenServiceEndpoint.private_tor(Mock(), 80,
                                                        control_port=1234)
        m.assert_called()

    @defer.inlineCallbacks
    def test_private_tor_no_control_port(self):
        m = Mock()
        from txtorcon import endpoints
        endpoints.launch_tor = m
        ep = yield TCPHiddenServiceEndpoint.private_tor(Mock(), 80)
        m.assert_called()

    @defer.inlineCallbacks
    def test_system_tor(self):
        from test_torconfig import FakeControlProtocol

        def boom(*args):
            # why does the new_callable thing need a callable that
            # returns a callable? Feels like I must be doing something
            # wrong somewhere...
            def bam(*args, **kw):
                return self.protocol
            return bam
        with patch('txtorcon.endpoints.launch_tor') as m:
            with patch('txtorcon.endpoints.build_tor_connection', new_callable=boom) as btc:
                client = clientFromString(self.reactor, "tcp:host=localhost:port=9050")
                ep = yield TCPHiddenServiceEndpoint.system_tor(self.reactor,
                                                               client, 80)
                port = yield ep.listen(NoOpProtocolFactory())
                toa = port.getHost()
                self.assertTrue(hasattr(toa, 'onion_uri'))
                self.assertTrue(hasattr(toa, 'onion_port'))
                port.startListening()
                str(port)
                port.tor_config
                m.assert_called()

    @defer.inlineCallbacks
    def test_basic(self):
        listen = RuntimeError("listen")
        connect = RuntimeError("connect")
        reactor = proto_helpers.RaisingMemoryReactor(listen, connect)
        reactor.addSystemEventTrigger = Mock()

        ep = TCPHiddenServiceEndpoint(reactor, self.config, 123)
        self.config.bootstrap()
        yield self.config.post_bootstrap
        self.assertTrue(IProgressProvider.providedBy(ep))

        try:
            port = yield ep.listen(NoOpProtocolFactory())
            self.fail("Should have been an exception")
        except RuntimeError as e:
            # make sure we called listenTCP not connectTCP
            self.assertEqual(e, listen)

        repr(self.config.HiddenServices)

    def test_progress_updates(self):
        config = TorConfig()
        ep = TCPHiddenServiceEndpoint(self.reactor, config, 123)

        self.assertTrue(IProgressProvider.providedBy(ep))
        prog = IProgressProvider(ep)
        ding = Mock()
        prog.add_progress_listener(ding)
        args = (50, "blarg", "Doing that thing we talked about.")
        # kind-of cheating, test-wise?
        ep._tor_progress_update(*args)
        ding.assert_called_with(*args)

    def test_multiple_listen(self):
        ep = TCPHiddenServiceEndpoint(self.reactor, self.config, 123)
        d0 = ep.listen(NoOpProtocolFactory())

        @defer.inlineCallbacks
        def more_listen(arg):
            yield arg.stopListening()
            d1 = ep.listen(NoOpProtocolFactory())

            def foo(arg):
                return arg
            d1.addBoth(foo)
            defer.returnValue(arg)
            return
        d0.addBoth(more_listen)
        self.config.bootstrap()

        def check(arg):
            self.assertEqual('127.0.0.1', ep.tcp_endpoint._interface)
        d0.addCallback(check).addErrback(self.fail)
        return d0

    def test_already_bootstrapped(self):
        self.config.bootstrap()

        ep = TCPHiddenServiceEndpoint(self.reactor, self.config, 123)
        d = ep.listen(NoOpProtocolFactory())
        return d

    @defer.inlineCallbacks
    def test_explicit_data_dir(self):
        config = TorConfig()
        td = tempfile.mkdtemp()
        ep = TCPHiddenServiceEndpoint(self.reactor, config, 123, td)

        # fake out some things so we don't actually have to launch + bootstrap
        class FakeTorProcessProtocol(object):
            tor_protocol = self.reactor.protocol
        process = FakeTorProcessProtocol()
        ep._launch_tor = Mock(return_value=process)
        config._update_proto(Mock())
        config.bootstrap()
        yield config.post_bootstrap

        # make sure listen() correctly configures our hidden-serivce
        # with the explicit directory we passed in above
        port = yield ep.listen(NoOpProtocolFactory())
        self.assertEqual(1, len(config.HiddenServices))
        self.assertEqual(config.HiddenServices[0].dir, td)
        shutil.rmtree(td)

    def test_failure(self):
        self.reactor.failures = 1
        ep = TCPHiddenServiceEndpoint(self.reactor, self.config, 123)
        d = ep.listen(NoOpProtocolFactory())
        self.config.bootstrap()
        d.addErrback(self.check_error)
        return d

    def check_error(self, failure):
        self.assertEqual(failure.type, error.CannotListenError)
        return None

    def test_parse_via_plugin(self):
        # make sure we have a valid thing from get_global_tor without actually launching tor
        config = TorConfig()
        config.post_bootstrap = defer.succeed(config)
        from txtorcon import torconfig
        torconfig._global_tor_config = None
        get_global_tor(self.reactor,
                       _tor_launcher=lambda react, config, prog: defer.succeed(config))
        ep = serverFromString(self.reactor, 'onion:88:localPort=1234:hiddenServiceDir=/foo/bar')
        self.assertEqual(ep.public_port, 88)
        self.assertEqual(ep.local_port, 1234)
        self.assertEqual(ep.hidden_service_dir, '/foo/bar')

    def test_parse_user_path(self):
        # this makes sure we expand users and symlinks in
        # hiddenServiceDir args. see Issue #77

        # make sure we have a valid thing from get_global_tor without actually launching tor
        config = TorConfig()
        config.post_bootstrap = defer.succeed(config)
        from txtorcon import torconfig
        torconfig._global_tor_config = None
        get_global_tor(self.reactor,
                       _tor_launcher=lambda react, config, prog: defer.succeed(config))
        ep = serverFromString(self.reactor, 'onion:88:localPort=1234:hiddenServiceDir=~/blam/blarg')
        # would be nice to have a fixed path here, but then would have
        # to run as a known user :/
        # maybe using the docker stuff to run integration tests better here?
        self.assertEqual(os.path.expanduser('~/blam/blarg'), ep.hidden_service_dir)

    def test_parse_relative_path(self):
        # this makes sure we convert a relative path to absolute
        # hiddenServiceDir args. see Issue #77

        # make sure we have a valid thing from get_global_tor without actually launching tor
        config = TorConfig()
        config.post_bootstrap = defer.succeed(config)
        from txtorcon import torconfig
        torconfig._global_tor_config = None
        get_global_tor(self.reactor,
                       _tor_launcher=lambda react, config, prog: defer.succeed(config))

        orig = os.path.realpath('.')
        try:
            with util.TempDir() as t:
                t = str(t)
                os.chdir(t)
                os.mkdir(os.path.join(t, 'foo'))
                os.mkdir(os.path.join(t, 'foo', 'blam'))

                ep = serverFromString(self.reactor, 'onion:88:localPort=1234:hiddenServiceDir=foo/blam')
                self.assertEqual(os.path.join(t, 'foo', 'blam'), ep.hidden_service_dir)

        finally:
            os.chdir(orig)


class EndpointLaunchTests(unittest.TestCase):

    def setUp(self):
        self.reactor = FakeReactorTcp(self)
        self.protocol = FakeControlProtocol([])

    def test_onion_address(self):
        addr = TorOnionAddress("foo.onion", 80)
        # just want to run these and assure they don't throw
        # exceptions.
        repr(addr)
        hash(addr)

    def test_onion_parse_unix_socket(self):
        r = Mock()
        ep = serverFromString(r, "onion:80:controlPort=/tmp/foo")

    @patch('txtorcon.TCPHiddenServiceEndpoint.system_tor')
    @patch('txtorcon.TCPHiddenServiceEndpoint.global_tor')
    @patch('txtorcon.TCPHiddenServiceEndpoint.private_tor')
    @defer.inlineCallbacks
    def test_endpoint_launch_tor(self, private_tor, global_tor, system_tor):
        """
        we just want to confirm that calling listen results in the
        spawning of a Tor process; the parsing/setup from string are
        checked elsewhere.
        """

        reactor = proto_helpers.MemoryReactor()
        ep = serverFromString(reactor, 'onion:8888')
        r = yield ep.listen(NoOpProtocolFactory())
        self.assertEqual(global_tor.call_count, 1)
        self.assertEqual(private_tor.call_count, 0)
        self.assertEqual(system_tor.call_count, 0)

    @patch('txtorcon.TCPHiddenServiceEndpoint.system_tor')
    @patch('txtorcon.TCPHiddenServiceEndpoint.global_tor')
    @patch('txtorcon.TCPHiddenServiceEndpoint.private_tor')
    @defer.inlineCallbacks
    def test_endpoint_connect_tor(self, private_tor, global_tor, system_tor):
        """
        similar to above test, we're confirming that an
        endpoint-string with 'controlPort=xxxx' in it calls the API
        that will connect to a running Tor.
        """

        reactor = proto_helpers.MemoryReactor()
        ep = serverFromString(reactor, 'onion:8888:controlPort=9055:localPort=1234')
        r = yield ep.listen(NoOpProtocolFactory())
        self.assertEqual(global_tor.call_count, 0)
        self.assertEqual(private_tor.call_count, 0)
        self.assertEqual(system_tor.call_count, 1)

        # unfortunately, we don't add the hidden-service
        # configurations until we've connected to the launched Tor
        # and bootstrapped a TorConfig object -- and that's a ton
        # of stuff to fake out. Most of that is covered by the
        # parsing tests (i.e. are we getting the right config
        # values from a server-endpoint-string)


# FIXME should probably go somewhere else, so other tests can easily use these.
class FakeProtocol(object):
    implements(IProtocol)

    def dataReceived(self, data):
        print "DATA", data

    def connectionLost(self, reason):
        print "LOST", reason

    def makeConnection(self, transport):
        print "MAKE", transport
        transport.protocol = self

    def connectionMade(self):
        print "MADE!"


class FakeAddress(object):
    implements(IAddress)

    compareAttributes = ('type', 'host', 'port')
    type = 'fakeTCP'

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def __repr__(self):
        return '%s(%r, %d)' % (
            self.__class__.__name__, self.host, self.port)

    def __hash__(self):
        return hash((self.type, self.host, self.port))


class FakeListeningPort(object):
    implements(IListeningPort)

    def __init__(self, port):
        self.port = port

    def startListening(self):
        self.factory.doStart()

    def stopListening(self):
        self.factory.doStop()

    def getHost(self):
        return FakeAddress('host', self.port)


def port_generator():
    for x in xrange(65535, 0, -1):
        yield x


from test_torconfig import FakeReactor  # FIXME
from test_torconfig import FakeProcessTransport  # FIXME
from test_torconfig import FakeControlProtocol  # FIXME


class FakeReactorTcp(FakeReactor):
    implements(IReactorTCP)

    failures = 0
    _port_generator = port_generator()

    def __init__(self, test):
        self.protocol = TorControlProtocol()
        self.protocol.connectionMade = lambda: None
        self.transport = proto_helpers.StringTransport()
        self.transport = FakeProcessTransport()
        self.transport.protocol = self.protocol

        def blam():
            self.protocol.outReceived("Bootstrap")
        self.transport.closeStdin = blam
        self.protocol.makeConnection(self.transport)
        FakeReactor.__init__(self, test, self.transport, lambda x: None)

    def listenTCP(self, port, factory, **kwargs):
        '''returns IListeningPort'''
        if self.failures > 0:
            self.failures -= 1
            raise error.CannotListenError(None, None, None)

        if port == 0:
            port = self._port_generator.next()
        p = FakeListeningPort(port)
        p.factory = factory
        p.startListening()
        return p

    def connectTCP(self, host, port, factory, timeout, bindAddress):
        '''should return IConnector'''
#        print "CONN", host, port, factory
#        print dir(factory)
#        print "XX", factory
        r = tcp.Connector(host, port, factory, timeout, bindAddress, reactor=self)
#        print dir(r)

        def blam(*args):
            print "BLAAAAAM", args
        r.connect = blam
        return r
