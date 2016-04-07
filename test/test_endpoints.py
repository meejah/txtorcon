import os
import shutil
import tempfile

from mock import patch
from mock import Mock, MagicMock

from zope.interface import implementer

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
from txtorcon import launch
from txtorcon import TCPHiddenServiceEndpoint
from txtorcon import TorClientEndpoint
from txtorcon import TorNotFound
from txtorcon import TCPHiddenServiceEndpointParser
from txtorcon import IProgressProvider
from txtorcon import TorOnionAddress
from txtorcon.util import NoOpProtocolFactory, py3k
from txtorcon.endpoints import get_global_tor                       # FIXME
from txtorcon.endpoints import default_tcp4_endpoint_generator
from txtorcon.endpoints import EphemeralHiddenServiceClient

from . import util


mock_add_onion_response = '''ServiceID=s3aoqcldyhju7dic\nPrivateKey=RSA1024:MIICXQIBAAKBgQDSb1NOcxPNV2GyVLaikkYIcvTIi4ZBaoF4pGAr67WiQP1kzobRthW9IKPmzru45rXUSQHjg3mGvRxE6s0tBqU6OfPCxEzRgCm/KGyxcipVtDbwpImYZfmOFu+tn4NmqXkB0J5n9/YnbcJCkV3gDOeQ2BPPe+kTuVrc24rUHgoX/QIDAQABAoGAFyXJyyJbdkX7aCtrX5ypeXpztK+sV/vIPCYQsiQeebeeZ/1T1TOrVn+Fp/jrq14teCmDvKwUrR6WQnp1kVNez0LFsCUohuiG0+Qj26Ach5GZR8K1nkqfOBEbH+3A3dCcDYETL9XnKCIaLrmVKlrFvB5dLbZv0MiCw+K6X2W6iKECQQDukfCUR7/GLmc5oyra61D0ROwhti9DBEVPsOvOFI0q07A+bGqXB7kOog0dPj6xO2V/6MPYvc59vWk5XwoVG+nJAkEA4c8psUrGefbs3iQxr0ge6r3f3SccSCfc/YjwTnmf8yCJ0PRYdirVl+WfG5AGfwDCwrDrelkScLhj/bWssvXWlQJAGs6DPeYiAl7McomHEzpFymzEK7WQ8fLU5vN2S527jwhiUWFVSMsxXBeRaavI15lY+lppRz1sqmxSGoQ3Wc/dIQJBAKbWz7FE1FytCtoe1+7wVJeQbuURzp2phmh1U0hIKNwUQH946ht1DpfKesJ8qbAQudXrrjCZuzw5oPeF0fHwHfkCQQC8GhO4mLGD+aLvmhPHD9owUsKhL7HHVHkEvPm2sNdQBvOR9iKNGsC91LT2h3AQ7Zse95Rn00HLNKFCu1nn8hEf\n'''


@implementer(IReactorCore)
class MockReactor(Mock):
    """
    Just so that our 'provides IReactorCore' assertions pass, but it's
    still "just a Mock".
    """
    pass


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
            'txtorcon.controller.find_tor_binary',
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
        ep = yield TCPHiddenServiceEndpoint.private_tor(MockReactor(), 80)
        self.assertEqual(None, ep.onion_private_key)
        self.assertEqual(None, ep.onion_uri)
        ep.hiddenservice = Mock()
        ep.hiddenservice.private_key = 'mumble'
        self.assertEqual('mumble', ep.onion_private_key)

    @patch('txtorcon.controller.launch')
    @defer.inlineCallbacks
    def test_private_tor(self, launch):
        ep = yield TCPHiddenServiceEndpoint.private_tor(
            MockReactor(), 80,
            control_port=1234,
        )
        self.assertTrue(launch.called)
        # XXX what about a second call, to confirm we call launch again?

    @patch('txtorcon.controller.launch')
    @defer.inlineCallbacks
    def test_private_tor_no_control_port(self, launch):
        @implementer(IReactorCore)
        class Reactor(Mock):
            pass
        ep = yield TCPHiddenServiceEndpoint.private_tor(MockReactor(), 80)
        self.assertTrue(launch.called)

    @defer.inlineCallbacks
    def test_system_tor(self):
        from .test_torconfig import FakeControlProtocol

        def boom(*args):
            # why does the new_callable thing need a callable that
            # returns a callable? Feels like I must be doing something
            # wrong somewhere...
            def bam(*args, **kw):
                return self.protocol
            return bam
        with patch('txtorcon.controller.launch') as launch_mock:
            with patch('txtorcon.endpoints.build_tor_connection', new_callable=boom) as btc:
                client = clientFromString(
                    self.reactor,
                    "tcp:host=localhost:port=9050"
                )
                ep = yield TCPHiddenServiceEndpoint.system_tor(self.reactor,
                                                               client, 80)
                d = ep.listen(NoOpProtocolFactory())
                self.assertEqual(1, len(self.protocol.commands))
                self.protocol.commands[0][1].callback(mock_add_onion_response)
                self.protocol.event_happened('HS_DESC', 'UPLOAD s3aoqcldyhju7dic x random_hs_dir')
                self.protocol.event_happened('HS_DESC', 'UPLOADED s3aoqcldyhju7dic x random_hs_dir')
                port = yield d

                toa = port.getHost()
#                self.assertTrue(hasattr(toa, 'clients'))
#                self.assertTrue(hasattr(toa, 'onion_port'))
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

    @patch('txtorcon.controller.launch')
    def _test_progress_updates_private_tor(self, tor):
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
        ep = TCPHiddenServiceEndpoint(self.reactor, self.config, 123, ephemeral=False)
        d0 = ep.listen(NoOpProtocolFactory())

        @defer.inlineCallbacks
        def more_listen(arg):
            yield arg.stopListening()
            d1 = ep.listen(NoOpProtocolFactory())
            self.assertEqual(2, len(self.protocol.commands))
            self.protocol.commands[1][1].callback(mock_add_onion_response)

            def foo(arg):
                return arg
            d1.addBoth(foo)
            defer.returnValue(arg)
            return
        d0.addBoth(more_listen)
        self.config.bootstrap()

        self.assertEqual(1, len(self.protocol.sets))
        self.protocol.commands[0][1].callback(mock_add_onion_response)
        self.protocol.events['HS_DESC']('UPLOAD s3aoqcldyhju7dic X X X')
        self.protocol.events['HS_DESC']('UPLOADED s3aoqcldyhju7dic X X X')

        def check(arg):
            self.assertEqual('127.0.0.1', ep.tcp_endpoint._interface)
            self.assertEqual(len(self.config.HiddenServices), 1)
        d0.addCallback(check).addErrback(self.fail)
        return d0

    def test_multiple_listen(self):
        ep = TCPHiddenServiceEndpoint(self.reactor, self.config, 123, ephemeral=False)
        d0 = ep.listen(NoOpProtocolFactory())

        @defer.inlineCallbacks
        def more_listen(arg):
            print("DING", arg)
            yield arg.stopListening()
            d1 = ep.listen(NoOpProtocolFactory())
            self.assertEqual(3, len(self.protocol.sets))

            def foo(arg):
                return arg
            d1.addBoth(foo)
            defer.returnValue(arg)
            return
        d0.addBoth(more_listen)
        self.config.bootstrap()

        self.assertEqual(3, len(self.protocol.sets))

        def check(arg):
            self.assertEqual('127.0.0.1', ep.tcp_endpoint._interface)
            self.assertEqual(len(self.config.HiddenServices), 1)
        d0.addCallback(check).addErrback(self.fail)
        return d0

    def test_multiple_listen_ephemeral(self):
        ep = TCPHiddenServiceEndpoint(self.reactor, self.config, 123, ephemeral=True)
        d0 = ep.listen(NoOpProtocolFactory())

        @defer.inlineCallbacks
        def more_listen(arg):
            yield arg.stopListening()
            d1 = ep.listen(NoOpProtocolFactory())
            self.assertEqual(2, len(self.protocol.commands))
            self.protocol.commands[1][1].callback(mock_add_onion_response)

            def foo(arg):
                return arg
            d1.addBoth(foo)
            defer.returnValue(arg)
            return
        d0.addBoth(more_listen)
        self.config.bootstrap()

        self.protocol.commands[0][1].callback(mock_add_onion_response)
        self.protocol.events['HS_DESC']('UPLOAD s3aoqcldyhju7dic X X X')
        self.protocol.events['HS_DESC']('UPLOADED s3aoqcldyhju7dic X X X')

        def check(arg):
            self.assertEqual('127.0.0.1', ep.tcp_endpoint._interface)
            self.assertEqual(len(self.config.EphemeralOnionServices), 2)
        d0.addCallback(check).addErrback(self.fail)
        return d0

    def test_already_bootstrapped(self):
        self.config.bootstrap()

        ep = TCPHiddenServiceEndpoint(self.reactor, self.config, 123)
        d = ep.listen(NoOpProtocolFactory())
        self.assertEqual(1, len(self.protocol.commands))
        self.protocol.commands[0][1].callback(mock_add_onion_response)
        self.protocol.event_happened('HS_DESC', 'UPLOAD s3aoqcldyhju7dic x random_hs_dir')
        self.protocol.event_happened('HS_DESC', 'UPLOADED s3aoqcldyhju7dic x random_hs_dir')
        return d

    @defer.inlineCallbacks
    def test_explicit_data_dir(self):
        tmpdir = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmpdir, 'hostname'), 'w') as f:
                f.write('public')

            config = TorConfig(self.protocol)
            ep = TCPHiddenServiceEndpoint(self.reactor, config, 123, tmpdir)

            # make sure listen() correctly configures our hidden-serivce
            # with the explicit directory we passed in above
            d = ep.listen(NoOpProtocolFactory())
#            self.assertEqual(1, len(self.protocol.commands))
#            self.protocol.commands[0][1].callback(mock_add_onion_response)
#            self.protocol.event_happened('HS_DESC', 'UPLOAD s3aoqcldyhju7dic x random_hs_dir')
#            self.protocol.event_happened('HS_DESC', 'UPLOADED s3aoqcldyhju7dic x random_hs_dir')
            port = yield d

            self.assertEqual(1, len(config.HiddenServices))
            self.assertEqual(config.HiddenServices[0].dir, tmpdir)
            self.assertEqual(config.HiddenServices[0].hostname, 'public')

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

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

    @defer.inlineCallbacks
    def test_stealth_auth(self):
        '''
        make sure we produce a HiddenService instance with stealth-auth
        lines if we had authentication specified in the first place.
        '''

        config = TorConfig(self.protocol)
        ep = TCPHiddenServiceEndpoint(
            self.reactor, config, 123, '/dev/null',
            stealth_auth=['alice', 'bob'],
            ephemeral=False,
        )

        # make sure listen() correctly configures our hidden-serivce
        # with the explicit directory we passed in above
        d = ep.listen(NoOpProtocolFactory())

        def foo(fail):
            print("ERROR", fail)
        d.addErrback(foo)
        port = yield d
        self.assertEqual(1, len(config.HiddenServices))
        self.assertEqual(config.HiddenServices[0].dir, '/dev/null')
        self.assertEqual(config.HiddenServices[0].authorize_client[0], 'stealth alice,bob')
        self.assertEqual(None, ep.onion_uri)
        # XXX cheating; private API
        config.HiddenServices[0]._hostname = 'oh my'
        self.assertEqual('oh my', ep.onion_uri)


class EndpointLaunchTests(unittest.TestCase):

    def setUp(self):
        self.reactor = FakeReactorTcp(self)
        self.protocol = FakeControlProtocol([])

    def test_onion_address(self):
        addr = TorOnionAddress(80, EphemeralHiddenServiceClient("foo.onion", "privatekey"))
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
@implementer(IProtocol)
class FakeProtocol(object):

    def dataReceived(self, data):
        print("DATA", data)

    def connectionLost(self, reason):
        print("LOST", reason)

    def makeConnection(self, transport):
        print("MAKE", transport)
        transport.protocol = self

    def connectionMade(self):
        print("MADE!")


@implementer(IAddress)
class FakeAddress(object):

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


@implementer(IListeningPort)
class FakeListeningPort(object):

    def __init__(self, port):
        self.port = port

    def startListening(self):
        self.factory.doStart()

    def stopListening(self):
        self.factory.doStop()

    def getHost(self):
        return FakeAddress('host', self.port)


def port_generator():
    # XXX six has xrange/range stuff?
    for x in range(65535, 0, -1):
        yield x


from .test_torconfig import FakeReactor  # FIXME put in util or something?
from .test_torconfig import FakeProcessTransport  # FIXME importing from other test sucks
from .test_torconfig import FakeControlProtocol  # FIXME


@implementer(IReactorTCP, IReactorCore)
class FakeReactorTcp(FakeReactor):

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
            port = next(self._port_generator)
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
            print("BLAAAAAM", args)
        r.connect = blam
        return r


class FakeTorSocksEndpoint(object):
    def __init__(self, *args, **kw):
        self.host = args[1]
        self.port = args[2]
        self.transport = None

        self.failure = kw.get('failure', None)
        self.accept_port = kw.get('accept_port', None)

    def connect(self, fac):
        self.factory = fac
        if self.accept_port:
            if self.port != self.accept_port:
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
    skip = "no txsocksx on py3" if py3k else None

    def test_client_connection_failed(self):
        """
        This test is equivalent to txsocksx's
        TestSOCKS4ClientEndpoint.test_clientConnectionFailed
        """
        def fail_tor_socks_endpoint_generator(*args, **kw):
            kw['failure'] = Failure(ConnectionRefusedError())
            return FakeTorSocksEndpoint(*args, **kw)
        endpoint = TorClientEndpoint('', 0, _proxy_endpoint_generator=fail_tor_socks_endpoint_generator)
        d = endpoint.connect(None)
        return self.assertFailure(d, ConnectionRefusedError)

    def test_client_connection_failed_user_password(self):
        """
        Same as above, but with a username/password.
        """
        def fail_tor_socks_endpoint_generator(*args, **kw):
            kw['failure'] = Failure(ConnectionRefusedError())
            return FakeTorSocksEndpoint(*args, **kw)
        endpoint = TorClientEndpoint(
            'invalid host', 0,
            socks_username='billy', socks_password='s333cure',
            _proxy_endpoint_generator=fail_tor_socks_endpoint_generator)
        d = endpoint.connect(None)
        return self.assertFailure(d, ConnectionRefusedError)

    def test_default_generator(self):
        # just ensuring the default generator doesn't blow up
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
        endpoints = []

        def tor_socks_endpoint_generator(*args, **kw):
            endpoints.append(FakeTorSocksEndpoint(*args, **kw))
            return endpoints[-1]
        endpoint = TorClientEndpoint('', 0, _proxy_endpoint_generator=tor_socks_endpoint_generator)
        endpoint.connect(Mock)
        self.assertEqual(1, len(endpoints))
        self.assertEqual(endpoints[0].transport.value(), '\x05\x01\x00')

    @patch('txtorcon.endpoints.SOCKS5ClientEndpoint')
    @defer.inlineCallbacks
    def test_success(self, socks5_factory):
        ep = MagicMock()
        gold_proto = object()
        ep.connect = MagicMock(return_value=gold_proto)
        socks5_factory.return_value = ep

        def tor_socks_endpoint_generator(*args, **kw):
            return FakeTorSocksEndpoint(*args, **kw)

        endpoint = TorClientEndpoint('', 0, _proxy_endpoint_generator=tor_socks_endpoint_generator)
        other_proto = yield endpoint.connect(MagicMock())
        self.assertEqual(other_proto, gold_proto)

    def test_good_port_retry(self):
        """
        This tests that our Tor client endpoint retry logic works correctly.
        We create a proxy endpoint that fires a ConnectionRefusedError
        unless the connecting port matches. We attempt to connect with the
        proxy endpoint for each port that the Tor client endpoint will try.
        """
        success_ports = TorClientEndpoint.socks_ports_to_try
        endpoints = []
        for port in success_ports:
            def tor_socks_endpoint_generator(*args, **kw):
                kw['accept_port'] = port
                kw['failure'] = Failure(ConnectionRefusedError())
                endpoints.append(FakeTorSocksEndpoint(*args, **kw))
                return endpoints[-1]
            endpoint = TorClientEndpoint('', 0, _proxy_endpoint_generator=tor_socks_endpoint_generator)
            endpoint.connect(None)
            self.assertEqual(endpoints[-1].transport.value(), '\x05\x01\x00')

    def test_bad_port_retry(self):
        """
        This tests failure to connect to the ports on the "try" list.
        """
        fail_ports = [1984, 666]
        for port in fail_ports:
            def tor_socks_endpoint_generator(*args, **kw):
                kw['accept_port'] = port
                kw['failure'] = Failure(ConnectionRefusedError())
                return FakeTorSocksEndpoint(*args, **kw)
            endpoint = TorClientEndpoint('', 0, _proxy_endpoint_generator=tor_socks_endpoint_generator)
            d = endpoint.connect(None)
            return self.assertFailure(d, ConnectionRefusedError)

    def test_good_no_guess_socks_port(self):
        """
        This tests that if a SOCKS port is specified, we *only* attempt to
        connect to that SOCKS port.
        """
        endpoints = []

        def tor_socks_endpoint_generator(*args, **kw):
            kw['accept_port'] = 6669
            kw['failure'] = Failure(ConnectionRefusedError())
            endpoints.append(FakeTorSocksEndpoint(*args, **kw))
            return endpoints[-1]
        endpoint = TorClientEndpoint('', 0, _proxy_endpoint_generator=tor_socks_endpoint_generator, socks_port=6669)
        endpoint.connect(None)
        self.assertEqual(1, len(endpoints))
        self.assertEqual(endpoints[-1].transport.value(), '\x05\x01\x00')

    def test_bad_no_guess_socks_port(self):
        """
        This tests that are connection fails if we try to connect to an unavailable
        specified SOCKS port... even if there is a valid SOCKS port listening on
        the socks_ports_to_try list.
        """
        def tor_socks_endpoint_generator(*args, **kw):
            kw['accept_port'] = 9050
            kw['failure'] = Failure(ConnectionRefusedError())
            return FakeTorSocksEndpoint(*args, **kw)
        endpoint = TorClientEndpoint('', 0, _proxy_endpoint_generator=tor_socks_endpoint_generator, socks_port=6669)
        d = endpoint.connect(None)
        self.assertFailure(d, ConnectionRefusedError)
