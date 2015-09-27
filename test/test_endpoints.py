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
from twisted.internet.error import ConnectionRefusedError
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
from txtorcon import TorClientEndpoint
from txtorcon import TorNotFound
from txtorcon import TCPHiddenServiceEndpointParser
from txtorcon import IProgressProvider
from txtorcon import TorOnionAddress
from txtorcon.util import NoOpProtocolFactory
from txtorcon.endpoints import get_global_tor                       # FIXME
from txtorcon.endpoints import default_tcp4_endpoint_generator

import util


connectionRefusedFailure = Failure(ConnectionRefusedError())


class EndpointTests(unittest.TestCase):

    def setUp(self):
        from txtorcon import endpoints
        endpoints._global_tor_config = None
        del endpoints._global_tor_lock
        endpoints._global_tor_lock = defer.DeferredLock()
        self.reactor = FakeReactorTcp(self)
        self.protocol = FakeControlProtocol([])
        self.protocol.event_happened('INFO', 'something craaaaaaazy')
        self.protocol.event_happened(
            'INFO',
            'connection_dir_client_reached_eof(): Uploaded rendezvous '
            'descriptor (status 200 ("Service descriptor (v2) stored"))'
        )
        self.config = TorConfig(self.protocol)
        self.protocol.answers.append(
            'config/names=\nHiddenServiceOptions Virtual'
        )
        self.protocol.answers.append('HiddenServiceOptions')
        self.patcher = patch(
            'txtorcon.torconfig.find_tor_binary',
            return_value='/not/tor'
        )
        self.patcher.start()

    def tearDown(self):
        from txtorcon import endpoints
        endpoints._global_tor_config = None
        del endpoints._global_tor_lock
        endpoints._global_tor_lock = defer.DeferredLock()
        self.patcher.stop()

    @defer.inlineCallbacks
    def test_global_tor(self):
        config = yield get_global_tor(
            Mock(),
            _tor_launcher=lambda x, y, z: True
        )
        self.assertEqual(0, config.SOCKSPort)

    @defer.inlineCallbacks
    def test_global_tor_error(self):
        config0 = yield get_global_tor(
            Mock(),
            _tor_launcher=lambda x, y, z: True
        )
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
        self.assertTrue(m.called)

    @defer.inlineCallbacks
    def test_private_tor_no_control_port(self):
        m = Mock()
        from txtorcon import endpoints
        endpoints.launch_tor = m
        ep = yield TCPHiddenServiceEndpoint.private_tor(Mock(), 80)
        self.assertTrue(m.called)

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
        with patch('txtorcon.endpoints.launch_tor') as launch_mock:
            with patch('txtorcon.endpoints.build_tor_connection', new_callable=boom) as btc:
                client = clientFromString(
                    self.reactor,
                    "tcp:host=localhost:port=9050"
                )
                ep = yield TCPHiddenServiceEndpoint.system_tor(self.reactor,
                                                               client, 80)
                port = yield ep.listen(NoOpProtocolFactory())
                toa = port.getHost()
                self.assertTrue(hasattr(toa, 'onion_uri'))
                self.assertTrue(hasattr(toa, 'onion_port'))
                port.startListening()
                str(port)
                port.tor_config
                # system_tor should be connecting to a running one,
                # *not* launching a new one.
                self.assertFalse(launch_mock.called)

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
        self.assertTrue(ding.called_with(*args))

    @patch('txtorcon.endpoints.launch_tor')
    def test_progress_updates_private_tor(self, tor):
        ep = TCPHiddenServiceEndpoint.private_tor(self.reactor, 1234)
        tor.call_args[1]['progress_updates'](40, 'FOO', 'foo to the bar')
        return ep

    def __test_progress_updates_system_tor(self):
        ep = TCPHiddenServiceEndpoint.system_tor(self.reactor, 1234)
        ep._tor_progress_update(40, "FOO", "foo to bar")
        return ep

    @patch('txtorcon.endpoints.get_global_tor')
    def test_progress_updates_global_tor(self, tor):
        ep = TCPHiddenServiceEndpoint.global_tor(self.reactor, 1234)
        tor.call_args[1]['progress_updates'](40, 'FOO', 'foo to the bar')
        return ep

    def test_hiddenservice_key_unfound(self):
        ep = TCPHiddenServiceEndpoint.private_tor(
            self.reactor,
            1234,
            hidden_service_dir='/dev/null'
        )

        # FIXME Mock() should work somehow for this, but I couldn't
        # make it "go"
        class Blam(object):
            @property
            def private_key(self):
                raise IOError("blam")
        ep.hiddenservice = Blam()
        self.assertEqual(ep.onion_private_key, None)
        return ep

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
            self.assertEqual(len(self.config.HiddenServices), 1)
        d0.addCallback(check).addErrback(self.fail)
        return d0

    def test_already_bootstrapped(self):
        self.config.bootstrap()
        ep = TCPHiddenServiceEndpoint(self.reactor, self.config, 123)
        d = ep.listen(NoOpProtocolFactory())
        return d

    @defer.inlineCallbacks
    def test_explicit_data_dir(self):
        config = TorConfig(self.protocol)
        ep = TCPHiddenServiceEndpoint(self.reactor, config, 123, '/dev/null')

        # make sure listen() correctly configures our hidden-serivce
        # with the explicit directory we passed in above
        d = ep.listen(NoOpProtocolFactory())

        def foo(fail):
            print "ERROR", fail
        d.addErrback(foo)
        port = yield d
        self.assertEqual(1, len(config.HiddenServices))
        self.assertEqual(config.HiddenServices[0].dir, '/dev/null')

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
        # make sure we have a valid thing from get_global_tor without
        # actually launching tor
        config = TorConfig()
        config.post_bootstrap = defer.succeed(config)
        from txtorcon import torconfig
        torconfig._global_tor_config = None
        get_global_tor(
            self.reactor,
            _tor_launcher=lambda react, config, prog: defer.succeed(config)
        )
        ep = serverFromString(
            self.reactor,
            'onion:88:localPort=1234:hiddenServiceDir=/foo/bar'
        )
        self.assertEqual(ep.public_port, 88)
        self.assertEqual(ep.local_port, 1234)
        self.assertEqual(ep.hidden_service_dir, '/foo/bar')

    def test_parse_user_path(self):
        # this makes sure we expand users and symlinks in
        # hiddenServiceDir args. see Issue #77

        # make sure we have a valid thing from get_global_tor without
        # actually launching tor
        config = TorConfig()
        config.post_bootstrap = defer.succeed(config)
        from txtorcon import torconfig
        torconfig._global_tor_config = None
        get_global_tor(
            self.reactor,
            _tor_launcher=lambda react, config, prog: defer.succeed(config)
        )
        ep = serverFromString(
            self.reactor,
            'onion:88:localPort=1234:hiddenServiceDir=~/blam/blarg'
        )
        # would be nice to have a fixed path here, but then would have
        # to run as a known user :/
        # maybe using the docker stuff to run integration tests better here?
        self.assertEqual(
            os.path.expanduser('~/blam/blarg'),
            ep.hidden_service_dir
        )

    def test_parse_relative_path(self):
        # this makes sure we convert a relative path to absolute
        # hiddenServiceDir args. see Issue #77

        # make sure we have a valid thing from get_global_tor without
        # actually launching tor
        config = TorConfig()
        config.post_bootstrap = defer.succeed(config)
        from txtorcon import torconfig
        torconfig._global_tor_config = None
        get_global_tor(
            self.reactor,
            _tor_launcher=lambda react, config, prog: defer.succeed(config)
        )

        orig = os.path.realpath('.')
        try:
            with util.TempDir() as t:
                t = str(t)
                os.chdir(t)
                os.mkdir(os.path.join(t, 'foo'))
                hsdir = os.path.join(t, 'foo', 'blam')
                os.mkdir(hsdir)

                ep = serverFromString(
                    self.reactor,
                    'onion:88:localPort=1234:hiddenServiceDir=foo/blam'
                )
                self.assertEqual(
                    os.path.realpath(hsdir),
                    ep.hidden_service_dir
                )

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
        ep = serverFromString(
            reactor,
            'onion:8888:controlPort=9055:localPort=1234'
        )
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


from test_torconfig import FakeReactor  # FIXME put in util or something?
from test_torconfig import FakeProcessTransport  # FIXME importing from other test sucks
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
        r = tcp.Connector(
            host, port, factory, timeout,
            bindAddress, reactor=self
        )

        def blam(*args):
            print "BLAAAAAM", args
        r.connect = blam
        return r


class FakeTorSocksEndpoint(object):
    def __init__(self, *args, **kw):
        self.host = args[1]
        self.port = args[2]
        self.transport = None

        self.failure = kw.get('failure', None)
        self.acceptPort = kw.get('acceptPort', None)

    def connect(self, fac):
        self.factory = fac
        if self.acceptPort:
            if self.port != self.acceptPort:
                return defer.fail(self.failure)
        else:
            if self.failure:
                return defer.fail(self.failure)
        self.proto = fac.buildProtocol(None)
        transport = proto_helpers.StringTransport()
        self.proto.makeConnection(transport)
        self.transport = transport
        return defer.succeed(self.proto)


class TestTorClientEndpoint(unittest.TestCase):

    def test_client_connection_failed(self):
        """
        This test is equivalent to txsocksx's
        TestSOCKS4ClientEndpoint.test_clientConnectionFailed
        """
        def FailTorSocksEndpointGenerator(*args, **kw):
            kw['failure'] = connectionRefusedFailure
            return FakeTorSocksEndpoint(*args, **kw)
        endpoint = TorClientEndpoint('', 0, _proxy_endpoint_generator=FailTorSocksEndpointGenerator)
        d = endpoint.connect(None)
        return self.assertFailure(d, ConnectionRefusedError)

    def test_client_connection_failed_user_password(self):
        """
        Same as above, but with a username/password.
        """
        def FailTorSocksEndpointGenerator(*args, **kw):
            kw['failure'] = connectionRefusedFailure
            return FakeTorSocksEndpoint(*args, **kw)
        endpoint = TorClientEndpoint(
            'invalid host', 0,
            socks_username='billy', socks_password='s333cure',
            _proxy_endpoint_generator=FailTorSocksEndpointGenerator)
        d = endpoint.connect(None)
        return self.assertFailure(d, ConnectionRefusedError)

    def test_default_generator(self):
        # just ensuring the default generator doesn't blow updoesn't blow up
        default_tcp4_endpoint_generator(None, 'foo.bar', 1234)

    def test_no_host(self):
        self.assertRaises(
            ValueError,
            TorClientEndpoint, None, None
        )

    def test_parser_basic(self):
        ep = clientFromString(None, 'tor:host=timaq4ygg2iegci7.onion:port=80:socksPort=9050')

        self.assertEqual(ep.host, 'timaq4ygg2iegci7.onion')
        self.assertEqual(ep.port, 80)
        self.assertEqual(ep.socks_port, 9050)

    def test_parser_user_password(self):
        epstring = 'tor:host=torproject.org:port=443' + \
                   ':socksUsername=foo:socksPassword=bar'
        ep = clientFromString(None, epstring)

        self.assertEqual(ep.host, 'torproject.org')
        self.assertEqual(ep.port, 443)
        self.assertEqual(ep.socks_username, 'foo')
        self.assertEqual(ep.socks_password, 'bar')

    def test_default_factory(self):
        """
        This test is equivalent to txsocksx's TestSOCKS5ClientEndpoint.test_defaultFactory
        """
        def TorSocksEndpointGenerator(*args, **kw):
            return FakeTorSocksEndpoint(*args, **kw)
        endpoint = TorClientEndpoint('', 0, _proxy_endpoint_generator=TorSocksEndpointGenerator)
        endpoint.connect(None)
        self.assertEqual(endpoint.tor_socks_endpoint.transport.value(), '\x05\x01\x00')

    def test_good_port_retry(self):
        """
        This tests that our Tor client endpoint retry logic works correctly.
        We create a proxy endpoint that fires a connectionRefusedFailure
        unless the connecting port matches. We attempt to connect with the
        proxy endpoint for each port that the Tor client endpoint will try.
        """
        success_ports = TorClientEndpoint.socks_ports_to_try
        for port in success_ports:
            def TorSocksEndpointGenerator(*args, **kw):
                kw['acceptPort'] = port
                kw['failure'] = connectionRefusedFailure
                return FakeTorSocksEndpoint(*args, **kw)
            endpoint = TorClientEndpoint('', 0, _proxy_endpoint_generator=TorSocksEndpointGenerator)
            endpoint.connect(None)
            self.assertEqual(endpoint.tor_socks_endpoint.transport.value(), '\x05\x01\x00')

    def test_bad_port_retry(self):
        """
        This tests failure to connect to the ports on the "try" list.
        """
        fail_ports = [1984, 666]
        for port in fail_ports:
            def TorSocksEndpointGenerator(*args, **kw):
                kw['acceptPort'] = port
                kw['failure'] = connectionRefusedFailure
                return FakeTorSocksEndpoint(*args, **kw)
            endpoint = TorClientEndpoint('', 0, _proxy_endpoint_generator=TorSocksEndpointGenerator)
            d = endpoint.connect(None)
            return self.assertFailure(d, ConnectionRefusedError)

    def test_good_no_guess_socks_port(self):
        """
        This tests that if a SOCKS port is specified, we *only* attempt to
        connect to that SOCKS port.
        """
        def TorSocksEndpointGenerator(*args, **kw):
            kw['acceptPort'] = 6669
            kw['failure'] = connectionRefusedFailure
            return FakeTorSocksEndpoint(*args, **kw)
        endpoint = TorClientEndpoint('', 0, _proxy_endpoint_generator=TorSocksEndpointGenerator, socks_port=6669)
        endpoint.connect(None)
        self.assertEqual(endpoint.tor_socks_endpoint.transport.value(), '\x05\x01\x00')

    def test_bad_no_guess_socks_port(self):
        """
        This tests that are connection fails if we try to connect to an unavailable
        specified SOCKS port... even if there is a valid SOCKS port listening on
        the socks_ports_to_try list.
        """
        def TorSocksEndpointGenerator(*args, **kw):
            kw['acceptPort'] = 9050
            kw['failure'] = connectionRefusedFailure
            return FakeTorSocksEndpoint(*args, **kw)
        endpoint = TorClientEndpoint('', 0, _proxy_endpoint_generator=TorSocksEndpointGenerator, socks_port=6669)
        d = endpoint.connect(None)
        self.assertFailure(d, ConnectionRefusedError)
