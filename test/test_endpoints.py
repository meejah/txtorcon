import os
import shutil
import tempfile

from mock import patch
from mock import Mock, MagicMock

from zope.interface import implementer

from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.internet import defer, error, task, tcp, unix
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.endpoints import UNIXClientEndpoint
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
from twisted.internet.interfaces import IStreamClientEndpoint

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
from txtorcon.util import NoOpProtocolFactory
from txtorcon.endpoints import get_global_tor                       # FIXME
from txtorcon.endpoints import _HAVE_TLS
from txtorcon.endpoints import EphemeralHiddenServiceClient
from txtorcon.circuit import TorCircuitEndpoint
from txtorcon.controller import Tor
from txtorcon.socks import _TorSocksFactory

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
        endpoints._global_tor = None
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
            'config/names=\nHiddenServiceOptions Virtual\nControlPort Integer'
        )
        self.protocol.answers.append('HiddenServiceOptions')
        # why do i have to pass a dict for this V but not this ^
        self.protocol.answers.append({'ControlPort': '37337'})
        self.config.bootstrap()
        self.patcher = patch(
            'txtorcon.controller.find_tor_binary',
            return_value='/not/tor'
        )
        self.patcher.start()
        return self.config.post_bootstrap

    def tearDown(self):
        from txtorcon import endpoints
        endpoints._global_tor_config = None
        del endpoints._global_tor_lock
        endpoints._global_tor_lock = defer.DeferredLock()
        self.patcher.stop()

    @defer.inlineCallbacks
    def test_global_tor(self):
        """
        XXX what does this really test?
        just 'testing' the happy-path?
        """
        tor = yield get_global_tor(
            Mock(),
            _tor_launcher=lambda reactor, **kw: Tor(reactor, self.config),
        )
        self.assertIs(tor.config, self.config)

    @defer.inlineCallbacks
    def test_global_tor_error(self):
        config0 = yield get_global_tor(
            Mock(),
            _tor_launcher=lambda reactor, **kw: Tor(reactor, self.config),
        )
        # now if we specify a control_port it should be an error since
        # the above should have launched one.
        try:
            config1 = yield get_global_tor(
                Mock(), control_port=111,
                _tor_launcher=lambda reactor, **kw: Tor(reactor, self.config),
            )
            self.fail()
        except RuntimeError as e:
            # should be an error
            pass

    @defer.inlineCallbacks
    def test_illegal_torconfig_instance(self):

        class NotTorConfig(object):
            "Definitely not a TorConfig"

        with self.assertRaises(RuntimeError) as ctx:
            ep = TCPHiddenServiceEndpoint(
                Mock(), NotTorConfig(), 80,
            )
            yield ep.listen(Mock())
        self.assertTrue('TorConfig instance' in str(ctx.exception))


    def test_inconsistent_options_two_auths(self):
        with self.assertRaises(ValueError) as ctx:
            foo = TCPHiddenServiceEndpoint(
                Mock(), Mock(), 80,
                stealth_auth=['alice', 'bob'],
                ephemeral=True,
            )
        self.assertTrue("don't support stealth_auth" in str(ctx.exception))

    def test_inconsistent_options_dir_and_ephemeral(self):
        with self.assertRaises(ValueError) as ctx:
            foo = TCPHiddenServiceEndpoint(
                Mock(), Mock(), 80,
                ephemeral=True,
                hidden_service_dir="/not/nothing",
            )
        self.assertTrue("incompatible with", str(ctx.exception))

    def test_inconsistent_options_priv_key_no_ephemeral(self):
        with self.assertRaises(ValueError) as ctx:
            foo = TCPHiddenServiceEndpoint(
                Mock(), Mock(), 80,
                hidden_service_dir="/not/nothing",
                private_key="RSA1024:deadbeef",
            )
        self.assertTrue("incompatible with", str(ctx.exception))

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

        config_patch = patch.object(
            TorConfig, 'from_protocol',
            MagicMock(return_value=self.config)
        )
        with patch('txtorcon.controller.launch') as launch_mock, config_patch:
            @implementer(IStreamClientEndpoint)
            class MockEndpoint(object):
                def connect(this, factory):
                    return self.protocol
            client = MockEndpoint()
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
            port.onion_service
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
    def test_progress_updates_private_tor(self, tor):
        ep = TCPHiddenServiceEndpoint.private_tor(self.reactor, 1234)
        tor.call_args[1]['progress_updates'](40, 'FOO', 'foo to the bar')
        return ep

    def test_progress_updates_system_tor(self):
        ep = TCPHiddenServiceEndpoint.system_tor(
            self.reactor,
            UNIXClientEndpoint(self.reactor, "/non/existant"),
            1234,
        )
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

    @defer.inlineCallbacks
    def test_multiple_listen(self):
        ep = TCPHiddenServiceEndpoint(self.reactor, self.config, 123, ephemeral=False)
        port0 = yield ep.listen(NoOpProtocolFactory())
        self.assertEqual(3, len(self.protocol.sets))
        responses = ['UPLOAD s3aoqcldyhju7dic X X X', 'UPLOADED s3aoqcldyhju7dic X X X']
        def add_event_listener(evt, cb):
            if evt == 'HS_DESC' and len(responses):
                cb(responses.pop())
        self.protocol.add_event_listener = add_event_listener

        yield port0.stopListening()
        port1 = yield ep.listen(NoOpProtocolFactory())

        self.assertEqual(port0.getHost().onion_port, port1.getHost().onion_port)
        self.assertEqual('127.0.0.1', ep.tcp_endpoint._interface)
        self.assertEqual(len(self.config.HiddenServices), 1)

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
        d1 = self.config.bootstrap()

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
            with open(os.path.join(tmpdir, 'private_key'), 'w') as f:
                f.write('I am a fake private key blob')

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
            _tor_launcher=lambda reactor, **kw: defer.succeed(Tor(reactor, config)),
        )
        ep = serverFromString(
            self.reactor,
            'onion:88:localPort=1234:hiddenServiceDir=/foo/bar'
        )
        self.assertEqual(ep.public_port, 88)
        self.assertEqual(ep.local_port, 1234)
        self.assertEqual(ep.hidden_service_dir, '/foo/bar')

    def test_parse_via_plugin_hsdir_and_key(self):
        with self.assertRaises(ValueError) as ctx:
            serverFromString(
                self.reactor,
                'onion:88:hiddenServiceDir=/dev/null:privateKey=deadbeef'
            )
        self.assertTrue('Only one of' in str(ctx.exception))

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
            _tor_launcher=lambda reactor, **kw: defer.succeed(Tor(reactor, config)),
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
            _tor_launcher=lambda reactor, **kw: defer.succeed(Tor(reactor, config)),
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

    def test_onion_address_key(self):
        addr = TorOnionAddress(80, EphemeralHiddenServiceClient("foo.onion", "privatekey"))
        self.assertEqual(addr.onion_key, "privatekey")

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


from .test_torconfig import FakeControlProtocol  # FIXME


@implementer(IReactorTCP, IReactorCore)
class FakeReactorTcp(object):#FakeReactor):

    failures = 0
    _port_generator = port_generator()

    def __init__(self, test):
        self.protocol = TorControlProtocol()
        self.protocol.connectionMade = lambda: None
        self.transport = proto_helpers.StringTransport()
        self.transport.protocol = self.protocol

        def blam():
            self.protocol.outReceived(b"Bootstrap")
        self.transport.closeStdin = blam
        self.protocol.makeConnection(self.transport)
        self.test = test

    def spawnProcess(self, processprotocol, bin, args, env, path,
                     uid=None, gid=None, usePTY=None, childFDs=None):
        self.protocol = processprotocol
        self.protocol.makeConnection(self.transport)
        self.transport.process_protocol = processprotocol
        return self.transport

    def addSystemEventTrigger(self, *args):
        self.test.assertEqual(args[0], 'before')
        self.test.assertEqual(args[1], 'shutdown')
        # we know this is just for the temporary file cleanup, so we
        # nuke it right away to avoid polluting /tmp by calling the
        # callback now.
        args[2]()

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

    def connectUNIX(self, address, factory, timeout=30, checkPID=0):
        '''should return IConnector'''
        r = unix.Connector(
            address, factory, timeout, self, checkPID,
        )

        def blam(*args):
            print("BLAAAAAM", args)
        r.connect = blam
        return r


class FakeTorSocksEndpoint(object):
    """
    This ctor signature matches TorSocksEndpoint even though we don't
    use it in the tests.
    """

    def __init__(self, socks_endpoint, host, port, tls=False, **kw):
        self.host = host
        self.port = port
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
        transport = proto_helpers.StringTransportWithDisconnection()
        self.proto.makeConnection(transport)
        self.transport = transport
        return defer.succeed(self.proto)


class FakeSocksProto(object):
    def __init__(self, done, host, port, method, factory):
        self.done = done
        self.host = host
        self.port = port
        self.method = method
        self.factory = factory

    def makeConnection(self, transport):
        proto = self.factory.buildProtocol('socks5 addr')
        self.done.callback(proto)


class TestTorCircuitEndpoint(unittest.TestCase):

    @defer.inlineCallbacks
    def test_circuit_failure(self):
        """
        If the circuit fails the error propagates
        """
        reactor = Mock()
        torstate = Mock()
        target = Mock()
        target.connect = Mock(return_value=defer.succeed(None))
        circ = Mock()
        circ.state = 'FAILED'
        src_addr = Mock()
        src_addr.host = 'host'
        src_addr.port = 1234
        target.get_address = Mock(return_value=defer.succeed(src_addr))
        stream = Mock()
        stream.source_port = 1234
        stream.source_addr = 'host'

        # okay, so we fire up our circuit-endpoint with mostly mocked
        # things, and a circuit that's already in 'FAILED' state.
        ep = TorCircuitEndpoint(reactor, torstate, circ, target)

        # should get a Failure from the connect()
        d = ep.connect(Mock())
        yield ep.attach_stream(stream, [circ])
        try:
            yield d
            self.fail("Should get exception")
        except RuntimeError as e:
            assert "unusable" in str(e)


    @defer.inlineCallbacks
    def test_circuit_stream_failure(self):
        """
        If the stream-attach fails the error propagates
        """
        reactor = Mock()
        torstate = Mock()
        target = Mock()
        target.connect = Mock(return_value=defer.succeed(None))
        circ = Mock()
        circ.state = 'FAILED'
        src_addr = Mock()
        src_addr.host = 'host'
        src_addr.port = 1234
        target.get_address = Mock(return_value=defer.succeed(src_addr))
        stream = Mock()
        stream.source_port = 1234
        stream.source_addr = 'host'

        # okay, so we fire up our circuit-endpoint with mostly mocked
        # things, and a circuit that's already in 'FAILED' state.
        ep = TorCircuitEndpoint(reactor, torstate, circ, target)

        # should get a Failure from the connect()
        d = ep.connect(Mock())
        ep.attach_stream_failure(stream, RuntimeError("a bad thing"))
        try:
            yield d
            self.fail("Should get exception")
        except RuntimeError as e:
            self.assertEqual("a bad thing", str(e))

    @defer.inlineCallbacks
    def test_success(self):
        """
        Connect a stream via a circuit
        """
        reactor = Mock()
        torstate = Mock()
        target = Mock()
        target.connect = Mock(return_value=defer.succeed('fake proto'))
        circ = Mock()
        circ.state = 'NEW'
        src_addr = Mock()
        src_addr.host = 'host'
        src_addr.port = 1234
        target.get_address = Mock(return_value=defer.succeed(src_addr))
        stream = Mock()
        stream.source_port = 1234
        stream.source_addr = 'host'

        # okay, so we fire up our circuit-endpoint with mostly mocked
        # things, and a circuit that's already in 'FAILED' state.
        ep = TorCircuitEndpoint(reactor, torstate, circ, target)

        # should get a Failure from the connect()
        d = ep.connect(Mock())
        yield ep.attach_stream(stream, [circ])
        proto = yield d
        self.assertEqual(proto, 'fake proto')


class TestTorClientEndpoint(unittest.TestCase):

    @patch('txtorcon.endpoints.get_global_tor')
    def test_client_connection_failed(self, ggt):
        """
        This test is equivalent to txsocksx's
        TestSOCKS4ClientEndpoint.test_clientConnectionFailed
        """
        tor_endpoint = FakeTorSocksEndpoint(
            None, "host123", 9050,
            failure=Failure(ConnectionRefusedError()),
        )
        reactor = Mock()
        endpoint = TorClientEndpoint(reactor, '', 0, socks_endpoint=tor_endpoint)
        d = endpoint.connect(None)
        return self.assertFailure(d, ConnectionRefusedError)

    def test_client_tls_but_no_tls(self):
        with patch('txtorcon.endpoints._HAVE_TLS', False):
            with self.assertRaises(ValueError) as ctx:
                TorClientEndpoint(Mock(), 'localhost', 1234, tls=True)
        self.assertTrue("don't have TLS" in str(ctx.exception))

    def test_client_connection_failed_user_password(self):
        """
        Same as above, but with a username/password.
        """
        tor_endpoint = FakeTorSocksEndpoint(
            None, "fakehose", 9050,
            failure=Failure(ConnectionRefusedError()),
        )
        reactor = Mock()
        endpoint = TorClientEndpoint(
            reactor, 'invalid host', 0,
            socks_username='billy', socks_password='s333cure',
            socks_endpoint = tor_endpoint)
        d = endpoint.connect(None)
        return self.assertFailure(d, ConnectionRefusedError)

    def test_no_host(self):
        self.assertRaises(
            ValueError,
            TorClientEndpoint, Mock(), None, None, Mock(),
        )

    def test_parser_basic(self):
        ep = clientFromString(None, 'tor:host=timaq4ygg2iegci7.onion:port=80')

        self.assertEqual(ep.host, 'timaq4ygg2iegci7.onion')
        self.assertEqual(ep.port, 80)
        # XXX what's "the Twisted way" to get the port out here?
        # XXX actually, why was this set to 9050 before? should do the guessing-thing...
        self.assertEqual(ep._socks_endpoint, None)

    def test_parser_user_password(self):
        epstring = 'tor:host=torproject.org:port=443' + \
                   ':socksUsername=foo:socksPassword=bar'
        ep = clientFromString(None, epstring)

        self.assertEqual(ep.host, 'torproject.org')
        self.assertEqual(ep.port, 443)
        self.assertEqual(ep._socks_username, 'foo')
        self.assertEqual(ep._socks_password, 'bar')

    def test_default_factory(self):
        """
        This test is equivalent to txsocksx's TestSOCKS5ClientEndpoint.test_defaultFactory
        """

        tor_endpoint = FakeTorSocksEndpoint(None, "fakehost", 9050)
        reactor = Mock()
        endpoint = TorClientEndpoint(reactor, '', 0, socks_endpoint=tor_endpoint)
        endpoint.connect(Mock)
        self.assertEqual(tor_endpoint.transport.value(), b'\x05\x01\x00')

    @defer.inlineCallbacks
    def test_success(self):
        with patch.object(_TorSocksFactory, "protocol", FakeSocksProto) as socks5_factory:
            tor_endpoint = FakeTorSocksEndpoint(Mock(), "fakehost", 9050)
            endpoint = TorClientEndpoint(Mock(), b'meejah.ca', 443, socks_endpoint=tor_endpoint)
            proto = yield endpoint.connect(MagicMock())
            self.assertTrue(isinstance(proto, FakeSocksProto))
            self.assertEqual(b"meejah.ca", proto.host)
            self.assertEqual(443, proto.port)
            self.assertEqual('CONNECT', proto.method)

    def test_good_port_retry(self):
        """
        This tests that our Tor client endpoint retry logic works correctly.
        We create a proxy endpoint that fires a ConnectionRefusedError
        unless the connecting port matches. We attempt to connect with the
        proxy endpoint for each port that the Tor client endpoint will try.
        """
        reactor = Mock()
        success_ports = TorClientEndpoint.socks_ports_to_try
        for port in success_ports:
            tor_endpoint = FakeTorSocksEndpoint(
                b"fakehost", "127.0.0.1", port,
                accept_port=port,
                failure=Failure(ConnectionRefusedError()),
            )

            endpoint = TorClientEndpoint(reactor, '', 0, socks_endpoint=tor_endpoint)
            endpoint.connect(Mock())
            self.assertEqual(tor_endpoint.transport.value(), b'\x05\x01\x00')

    def test_bad_port_retry(self):
        """
        This tests failure to connect to the ports on the "try" list.
        """
        fail_ports = [1984, 666]
        reactor = Mock()
        for port in fail_ports:
            ep = FakeTorSocksEndpoint(
                '', '', 0,
                accept_port=port,
                failure=Failure(ConnectionRefusedError()),
            )
            endpoint = TorClientEndpoint(reactor, '', 0, socks_endpoint=ep)
            d = endpoint.connect(None)
            return self.assertFailure(d, ConnectionRefusedError)

    @patch('txtorcon.endpoints.TorSocksEndpoint')
    def test_default_socks_ports_fails(self, ep_mock):
        """
        Ensure we iterate over the default socks ports
        """

        class FakeSocks5(object):

            def __init__(self, *args, **kw):
                pass

            def connect(self, *args, **kw):
                raise ConnectionRefusedError()

        ep_mock.side_effect = FakeSocks5
        reactor = Mock()
        endpoint = TorClientEndpoint(reactor, '', 0)#, socks_endpoint=ep)
        d = endpoint.connect(Mock())
        self.assertFailure(d, ConnectionRefusedError)

    @patch('txtorcon.endpoints.TorSocksEndpoint')
    @defer.inlineCallbacks
    def test_default_socks_ports_happy(self, ep_mock):
        """
        Ensure we iterate over the default socks ports
        """

        proto = object()
        class FakeSocks5(object):

            def __init__(self, *args, **kw):
                pass

            def connect(self, *args, **kw):
                return proto

        ep_mock.side_effect = FakeSocks5
        reactor = Mock()
        endpoint = TorClientEndpoint(reactor, '', 0)
        p2 = yield endpoint.connect(None)
        self.assertTrue(proto is p2)

    @patch('txtorcon.endpoints.TorSocksEndpoint')
    @defer.inlineCallbacks
    def test_tls_socks_no_endpoint(self, ep_mock):

        if not _HAVE_TLS:
            print("no TLS support")
            return

        class FakeWrappedProto(object):
            wrappedProtocol = object()

        wrap = FakeWrappedProto()
        proto = defer.succeed(wrap)
        class FakeSocks5(object):

            def __init__(self, *args, **kw):
                pass

            def connect(self, *args, **kw):
                return proto

        ep_mock.side_effect = FakeSocks5
        reactor = Mock()
        endpoint = TorClientEndpoint(reactor, 'torproject.org', 0, tls=True)
        p2 = yield endpoint.connect(None)
        self.assertTrue(wrap.wrappedProtocol is p2)

    @patch('txtorcon.endpoints.TorSocksEndpoint')
    @defer.inlineCallbacks
    def test_tls_socks_with_endpoint(self, ep_mock):
        """
        Same as above, except we provide an explicit endpoint
        """

        if not _HAVE_TLS:
            print("no TLS support")
            return

        class FakeWrappedProto(object):
            wrappedProtocol = object()

        wrap = FakeWrappedProto()
        proto = defer.succeed(wrap)
        class FakeSocks5(object):

            def __init__(self, *args, **kw):
                pass

            def connect(self, *args, **kw):
                return proto

        reactor = Mock()
        ep_mock.side_effect = FakeSocks5
        endpoint = TorClientEndpoint(
            reactor,
            'torproject.org', 0,
            socks_endpoint=clientFromString(Mock(), "tcp:localhost:9050"),
            tls=True,
        )
        p2 = yield endpoint.connect(None)
        self.assertTrue(wrap.wrappedProtocol is p2)

    def test_client_endpoint_old_api(self):
        """
        Test the old API of passing socks_host, socks_port
        """

        reactor = Mock()
        endpoint = TorClientEndpoint(
            reactor, 'torproject.org', 0,
            socks_hostname='localhost',
            socks_port=9050,
        )
        self.assertTrue(isinstance(endpoint._socks_endpoint, TCP4ClientEndpoint))

        d = endpoint.connect(Mock())
        calls = reactor.mock_calls
        self.assertEqual(1, len(calls))
        name, args, kw = calls[0]
        self.assertEqual("connectTCP", name)
        self.assertEqual("localhost", args[0])
        self.assertEqual(9050, args[1])
