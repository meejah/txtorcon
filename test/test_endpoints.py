from __future__ import print_function

import os
import sys
from mock import patch
from mock import Mock, MagicMock
from unittest import skipIf
from binascii import b2a_base64

from zope.interface import implementer, directlyProvides

from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.internet import defer, error, tcp, unix
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.endpoints import UNIXClientEndpoint
from twisted.internet.endpoints import serverFromString
from twisted.internet.endpoints import clientFromString
from twisted.python.failure import Failure
from twisted.internet.error import ConnectionRefusedError
from twisted.internet.interfaces import IStreamClientEndpoint
from twisted.internet.interfaces import IReactorCore
from twisted.internet.interfaces import IProtocol
from twisted.internet.interfaces import IReactorTCP
from twisted.internet.interfaces import IListeningPort
from twisted.internet.interfaces import IAddress

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from txtorcon import TorControlProtocol
from txtorcon import TorConfig
from txtorcon import TCPHiddenServiceEndpoint
from txtorcon import TorClientEndpoint
# from txtorcon import TorClientEndpointStringParser
from txtorcon import IProgressProvider
from txtorcon import TorOnionAddress
from txtorcon.onion import IAuthenticatedOnionClients
from txtorcon.onion import IOnionService
from txtorcon.onion import _compute_permanent_id
from txtorcon import AuthStealth
from txtorcon import AuthBasic
from txtorcon.util import NoOpProtocolFactory
from txtorcon.util import SingleObserver
from txtorcon.endpoints import get_global_tor                       # FIXME
from txtorcon.endpoints import _create_socks_endpoint
from txtorcon.circuit import TorCircuitEndpoint, _get_circuit_attacher
from txtorcon.controller import Tor
from txtorcon.socks import _TorSocksFactory

from . import util
from .test_onion import _test_private_key       # put in testutil?
from .test_onion import _test_private_key_blob  # put in testutil?
from .test_onion import _test_onion_id          # put in testutil?
from txtorcon.testutil import FakeControlProtocol


@implementer(IReactorCore)
class MockReactor(Mock):
    """
    Just so that our 'provides IReactorCore' assertions pass, but it's
    still "just a Mock".
    """
    pass


@patch('txtorcon.controller.find_tor_binary', return_value='/bin/echo')
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
        self.protocol.answers.append(
            'config/names=\nHiddenServiceOptions Virtual\nControlPort LineList\nSOCKSPort LineList'
        )
        self.protocol.answers.append('config/defaults=')
        self.protocol.answers.append('HiddenServiceOptions')
        # why do i have to pass a dict for this V but not this ^
        self.protocol.answers.append({'ControlPort': '37337'})
        self.protocol.answers.append({'SOCKSPort': '9050'})
        self.protocol.answers.append({'onions/detached': ''})
        self.protocol.answers.append({'onions/current': ''})
        self.patcher = patch(
            'txtorcon.controller.find_tor_binary',
            return_value='/not/tor'
        )
        self.patcher.start()
        self.config = TorConfig(self.protocol)
        d = defer.Deferred()
        self.config.post_bootstrap.addCallback(lambda _: d.callback(self.config))
        return d

    def tearDown(self):
        from txtorcon import endpoints
        endpoints._global_tor_config = None
        del endpoints._global_tor_lock
        endpoints._global_tor_lock = defer.DeferredLock()
        self.patcher.stop()

    @defer.inlineCallbacks
    def test_global_tor(self, ftb):
        fake_tor = Mock()
        fake_tor.get_config = Mock(return_value=self.config)
        config = yield get_global_tor(
            Mock(),
            _tor_launcher=lambda x, progress_updates=None: fake_tor
        )
        # XXX this was asserting SOCKSPort == 0 before; why?
        self.assertEqual(['9050'], config.SOCKSPort)

    @defer.inlineCallbacks
    def test_global_tor_error(self, ftb):
        yield get_global_tor(
            reactor=FakeReactorTcp(self),
            _tor_launcher=lambda x, y, progress_updates=None: True
        )
        # now if we specify a control_port it should be an error since
        # the above should have launched one.
        try:
            yield get_global_tor(
                reactor=FakeReactorTcp(self),
                control_port=111,
                _tor_launcher=lambda x, y, progress_updates=None: True
            )
            self.fail()
        except RuntimeError:
            # should be an error
            pass

    @defer.inlineCallbacks
    def test_endpoint_properties(self, ftb):
        ep = yield TCPHiddenServiceEndpoint.private_tor(self.reactor, 80)
        self.assertEqual(None, ep.onion_private_key)
        self.assertEqual(None, ep.onion_uri)
        ep.hiddenservice = Mock()
        ep.hiddenservice.private_key = 'mumble'
        self.assertEqual('mumble', ep.onion_private_key)

    @defer.inlineCallbacks
    def test_private_tor(self, ftb):
        with patch('txtorcon.endpoints._global_tor_config'):
            with patch('txtorcon.controller.launch') as launch:
                m = Mock()
                directlyProvides(m, IReactorCore)
                yield TCPHiddenServiceEndpoint.private_tor(
                    reactor=m,
                    public_port=80,
                    control_port=1234,
                )
                self.assertTrue(launch.called)

    @defer.inlineCallbacks
    def test_private_tor_no_control_port(self, ftb):
        with patch('txtorcon.endpoints._global_tor_config'):
            with patch('txtorcon.controller.launch') as launch:
                yield TCPHiddenServiceEndpoint.private_tor(self.reactor, 80)
                self.assertTrue(len(launch.mock_calls) > 1)

    @defer.inlineCallbacks
    def test_system_tor(self, ftb):

        def boom():
            # why does the new_callable thing need a callable that
            # returns a callable? Feels like I must be doing something
            # wrong somewhere...
            def bam(*args, **kw):
                self.config.bootstrap()
                return defer.succeed(Tor(Mock(), self.protocol, _tor_config=self.config))
            return bam
        with patch('txtorcon.controller.launch') as launch_mock:
            with patch('txtorcon.controller.connect', new_callable=boom):
                client = clientFromString(
                    self.reactor,
                    "tcp:host=localhost:port=9050"
                )
                ep = yield TCPHiddenServiceEndpoint.system_tor(self.reactor,
                                                               client, 80)
                port_d = ep.listen(NoOpProtocolFactory())
                self.protocol.commands[0][1].callback("ServiceID=service\nPrivateKey=blob")
                self.protocol.events['HS_DESC']('UPLOAD service x x x x')
                self.protocol.events['HS_DESC']('UPLOADED service x x x x')
                port = yield port_d
                toa = port.getHost()
                self.assertTrue(hasattr(toa, 'onion_uri'))
                self.assertTrue(hasattr(toa, 'onion_port'))
                port.startListening()
                str(port)
                port.tor_config
                port.local_address
                with self.assertRaises(ValueError) as ctx:
                    port.hidden_service_dir
                self.assertIn(
                    "our _service doesn't provide IFilesystemOnionService",
                    str(ctx.exception)
                )
                # system_tor should be connecting to a running one,
                # *not* launching a new one.
                self.assertFalse(launch_mock.called)

    @defer.inlineCallbacks
    def test_system_tor_explit_dir_not_exist(self, ftb):
        # same as above, but we pass an explicit (but non-existent)
        # hsdir and then simulate Tor creating it...

        def boom():
            # why does the new_callable thing need a callable that
            # returns a callable? Feels like I must be doing something
            # wrong somewhere...
            def bam(*args, **kw):
                self.config.bootstrap()
                return defer.succeed(Tor(Mock(), self.protocol, _tor_config=self.config))
            return bam
        hsdir = self.mktemp()  # not creating it
        with patch('txtorcon.controller.launch') as launch_mock:
            with patch('txtorcon.controller.connect', new_callable=boom):
                client = clientFromString(
                    self.reactor,
                    "tcp:host=localhost:port=9050"
                )
                ep = yield TCPHiddenServiceEndpoint.system_tor(self.reactor,
                                                               client, 80, hidden_service_dir=hsdir)
                port_d = ep.listen(NoOpProtocolFactory())

                # Tor would create the hsdir "approximately now"
                os.mkdir(hsdir)
                with open(os.path.join(hsdir, "hostname"), "w") as f:
                    f.write("service.onion\n")

                self.protocol.events['HS_DESC']('UPLOAD service x x x x')
                self.protocol.events['HS_DESC']('UPLOADED service x x x x')
                port = yield port_d
                toa = port.getHost()
                self.assertTrue(hasattr(toa, 'onion_uri'))
                self.assertTrue(hasattr(toa, 'onion_port'))
                port.startListening()
                str(port)
                port.tor_config
                port.hidden_service_dir
                # system_tor should be connecting to a running one,
                # *not* launching a new one.
                self.assertFalse(launch_mock.called)

    @defer.inlineCallbacks
    def test_system_tor_explit_dir_not_readable0(self, ftb):
        # same as above, but we pass an explicit (but non-existent)
        # hsdir and then simulate Tor creating it...

        def boom():
            # why does the new_callable thing need a callable that
            # returns a callable? Feels like I must be doing something
            # wrong somewhere...
            def bam(*args, **kw):
                self.config.bootstrap()
                return defer.succeed(Tor(Mock(), self.protocol, _tor_config=self.config))
            return bam
        hsdir = self.mktemp()
        os.mkdir(hsdir)

        with patch('txtorcon.controller.launch') as launch_mock:
            with patch('txtorcon.controller.connect', new_callable=boom):
                client = clientFromString(
                    self.reactor,
                    "tcp:host=localhost:port=9050"
                )
                ep = yield TCPHiddenServiceEndpoint.system_tor(self.reactor,
                                                               client, 80, hidden_service_dir=hsdir)
                port_d = ep.listen(NoOpProtocolFactory())

                fname = os.path.join(hsdir, "hostname")
                with open(fname, 'w') as f:
                    f.write("service.onion")

                self.protocol.events['HS_DESC']('UPLOAD service x x x x')
                self.protocol.events['HS_DESC']('UPLOADED service x x x x')

                port = yield port_d
                toa = port.getHost()
                self.assertTrue(hasattr(toa, 'onion_uri'))
                self.assertTrue(hasattr(toa, 'onion_port'))
                port.startListening()
                str(port)
                port.tor_config
                # system_tor should be connecting to a running one,
                # *not* launching a new one.
                self.assertFalse(launch_mock.called)

                # make it re-read the hostname information
                ep.hiddenservice._hostname = None
                # make an IOError happen when we try to read the hostname
                os.chmod(fname, 0x0)
                # ...but this eats it and returns None
                self.assertIs(None, ep.onion_uri)

    @defer.inlineCallbacks
    def test_system_tor_explit_dir_not_readable_version3(self, ftb):
        # same as above, but we pass an explicit (but non-existent)
        # hsdir and then simulate Tor creating it...

        def boom():
            # why does the new_callable thing need a callable that
            # returns a callable? Feels like I must be doing something
            # wrong somewhere...
            def bam(*args, **kw):
                self.config.bootstrap()
                return defer.succeed(Tor(Mock(), self.protocol, _tor_config=self.config))
            return bam
        hsdir = self.mktemp()
        os.mkdir(hsdir)

        with patch('txtorcon.controller.launch') as launch_mock:
            with patch('txtorcon.controller.connect', new_callable=boom):
                client = clientFromString(
                    self.reactor,
                    "tcp:host=localhost:port=9050"
                )
                ep = yield TCPHiddenServiceEndpoint.system_tor(self.reactor,
                                                               client, 80, hidden_service_dir=hsdir)
                port_d = ep.listen(NoOpProtocolFactory())

                fname = os.path.join(hsdir, "hostname")
                with open(fname, 'w') as f:
                    f.write("service.onion")

                self.protocol.events['HS_DESC']('UPLOAD service x x x x')
                self.protocol.events['HS_DESC']('UPLOADED service x x x x')

                # make it re-read the hostname information
                ep.hiddenservice._hostname = None
                # make an IOError happen when we try to read the hostname
                os.chmod(fname, 0x0)

                port = yield port_d
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
    def test_explit_dir_not_readable_version2(self, ftb):

        def boom():
            # why does the new_callable thing need a callable that
            # returns a callable? Feels like I must be doing something
            # wrong somewhere...
            def bam(*args, **kw):
                self.config.bootstrap()
                return defer.succeed(Tor(Mock(), self.protocol, _tor_config=self.config))
            return bam
        hsdir = self.mktemp()
        os.mkdir(hsdir)

        with patch('txtorcon.controller.launch') as launch_mock:
            with patch('txtorcon.controller.connect', new_callable=boom):
                client = clientFromString(
                    self.reactor,
                    "tcp:host=localhost:port=9050"
                )
                ep = yield TCPHiddenServiceEndpoint.system_tor(
                    self.reactor, client, 80,
                    hidden_service_dir=hsdir,
                    version=2,
                )
                port_d = ep.listen(NoOpProtocolFactory())

                fname = os.path.join(hsdir, "hostname")
                with open(fname, 'w') as f:
                    f.write("service.onion")

                self.protocol.events['HS_DESC']('UPLOAD service x x x x')
                self.protocol.events['HS_DESC']('UPLOADED service x x x x')

                # make it re-read the hostname information
                ep.hiddenservice._hostname = None
                # make an IOError happen when we try to read the hostname
                os.chmod(fname, 0x0)

                fname = os.path.join(hsdir, "private_key")
                with open(fname, 'w') as f:
                    f.write("privkey")
                os.chmod(fname, 0x0)

                port = yield port_d
                toa = port.getHost()
                self.assertTrue(hasattr(toa, 'onion_uri'))
                self.assertTrue(hasattr(toa, 'onion_port'))
                port.startListening()
                str(port)
                port.tor_config
                # system_tor should be connecting to a running one,
                # *not* launching a new one.
                self.assertFalse(launch_mock.called)
                self.assertIs(None, port.onion_service.private_key)

    @defer.inlineCallbacks
    def test_basic(self, ftb):
        listen = RuntimeError("listen")
        connect = RuntimeError("connect")
        reactor = proto_helpers.RaisingMemoryReactor(listen, connect)
        reactor.addSystemEventTrigger = Mock()

        ep = TCPHiddenServiceEndpoint(reactor, self.config, 123)
        assert self.config.post_bootstrap.called
        yield self.config.post_bootstrap
        self.assertTrue(IProgressProvider.providedBy(ep))

        try:
            yield ep.listen(NoOpProtocolFactory())
            self.fail("Should have been an exception")
        except RuntimeError as e:
            # make sure we called listenTCP not connectTCP
            self.assertEqual(e, listen)

        repr(self.config.HiddenServices)

    @defer.inlineCallbacks
    def test_basic_auth(self, ftb):
        reactor = proto_helpers.MemoryReactor()
        reactor.addSystemEventTrigger = Mock()
        privkey = (
            b'-----BEGIN RSA PRIVATE KEY-----\n'
            b'MIICXAIBAAKBgQC+bxV7+iEjJCmvQW/2SOYFQBsF06VuAdVKr3xTNMHgqI5mks6O\n'
            b'D8cizQ1nr0bL/bqtLPA2whUSvaJmDZjkmpC62v90YU1p99tGOv+ILZTzoIIjcWWn\n'
            b'3muDzA7p+zlN50x55ABuxEwQ3TfRA6nM1JF4HamYuHNae5nzbdwuxXpQ4wIDAQAB\n'
            b'AoGBAJLjbkf11M+dWkXjjLAE5OAR5YYmDYmAAnycRaKMpCtc+JIoFQlBJFI0pm1e\n'
            b'ppY8fVyMuDEUnVqaSYS8Yj2a95zD84hr0SzNFf5wSbffEcLIsmw7I18Mxq/YMrmy\n'
            b'oGwizMnhV/IVPKh40xctPl2cIpg9AdBLYgnc/sO8oBr5k+uRAkEA8B4jeVq4IYv/\n'
            b'b/kPzWiav/9weFMqKZdDh0O7ashbRe4b6CaHI2+XxX4uop9bFCTXsq73yCL7gqpU\n'
            b'AkzCPGWvmwJBAMsHqQQjKn7KlPezZsYL4FY2IkqKuq2x6vFWhMPfXl6y66Ya6/uO\n'
            b'of5kJUlolVcbvAEq4kLAk7nWi9RzWux/DFkCQHk1HX8StkPo4YZqWPm9RfCJRwLW\n'
            b'KEBaZPIQ1LhwbvJ74YZsfGb828YLjgr1GgqvFlrSS62xSviIdmO6z4mhYuUCQAK9\n'
            b'E7aOkuAq819z+Arr1hbTnBrNTD9Tiwu+UwQhWzCD0VHoQw6dmenIiAg5dOo74YlS\n'
            b'fsLPvi5fintPIwbVn+ECQCh6PEvaTP+fsPTyaRPOftCPqgLZbfzGnmt3ZJh1EB60\n'
            b'6X5Sz7FXRbQ8G5kmBy7opEoT4vsLMWGI+uq5WCXiuqY=\n'
            b'-----END RSA PRIVATE KEY-----\n'
        )
        perm_id = _compute_permanent_id(
            serialization.load_pem_private_key(
                privkey,
                password=None,
                backend=default_backend(),
            )
        )
        hsdir = self.mktemp()
        os.mkdir(hsdir)
        with open(os.path.join(hsdir, 'private_key'), 'wb') as f:
            f.write(privkey)

        ep = TCPHiddenServiceEndpoint(
            reactor, self.config, 123,
            ephemeral=False,
            hidden_service_dir=hsdir,
            auth=AuthBasic(['alice', 'bob']),
        )
        assert self.config.post_bootstrap.called
        yield self.config.post_bootstrap
        self.assertTrue(IProgressProvider.providedBy(ep))

        port_d = ep.listen(NoOpProtocolFactory())
        self.assertEqual(4, len(self.protocol.sets))
        hsdesc = self.protocol.events['HS_DESC']
        hsdesc("UPLOAD {} x x x x".format(perm_id))
        hsdesc("UPLOADED {} x x x x".format(perm_id))
        yield port_d

    @defer.inlineCallbacks
    def test_not_ephemeral_no_hsdir(self, ftb):
        listen = RuntimeError("listen")
        connect = RuntimeError("connect")
        reactor = proto_helpers.RaisingMemoryReactor(listen, connect)
        reactor.addSystemEventTrigger = Mock()

        ep = TCPHiddenServiceEndpoint(reactor, self.config, 123, ephemeral=False)
        assert self.config.post_bootstrap.called
        yield self.config.post_bootstrap
        self.assertTrue(IProgressProvider.providedBy(ep))

        try:
            yield ep.listen(NoOpProtocolFactory())
            self.fail("Should have been an exception")
        except RuntimeError as e:
            # make sure we called listenTCP not connectTCP
            self.assertEqual(e, listen)

        repr(self.config.HiddenServices)

    def test_progress_updates(self, ftb):
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

    def test_progress_updates_error(self, ftb):
        config = TorConfig()
        ep = TCPHiddenServiceEndpoint(self.reactor, config, 123)

        self.assertTrue(IProgressProvider.providedBy(ep))
        prog = IProgressProvider(ep)

        class CustomBadness(Exception):
            pass

        def boom(*args, **kw):
            raise CustomBadness("the bad stuff")
        prog.add_progress_listener(boom)
        args = (50, "blarg", "Doing that thing we talked about.")
        # kind-of cheating, test-wise?
        ep._tor_progress_update(*args)
        ep._descriptor_progress_update(*args)
        # if we ignore the progress-listener error: success
        errs = self.flushLoggedErrors(CustomBadness)
        self.assertEqual(2, len(errs))

    def test_progress_updates_private_tor(self, ftb):
        with patch('txtorcon.controller.launch') as tor:
            with patch('txtorcon.endpoints._global_tor_config'):
                ep = TCPHiddenServiceEndpoint.private_tor(self.reactor, 1234)
                self.assertTrue(len(tor.mock_calls) > 1)
                tor.mock_calls[0][2]['progress_updates'](40, 'FOO', 'foo to the bar')
                return ep

    def test_progress_updates_system_tor(self, ftb):
        control_ep = Mock()
        control_ep.connect = Mock(return_value=defer.succeed(None))
        directlyProvides(control_ep, IStreamClientEndpoint)
        ep = TCPHiddenServiceEndpoint.system_tor(self.reactor, control_ep, 1234)
        ep._tor_progress_update(40, "FOO", "foo to bar")
        return ep

    def test_single_hop_non_ephemeral(self, ftb):
        control_ep = Mock()
        control_ep.connect = Mock(return_value=defer.succeed(None))
        directlyProvides(control_ep, IStreamClientEndpoint)
        with self.assertRaises(ValueError) as ctx:
            TCPHiddenServiceEndpoint.system_tor(
                self.reactor, control_ep, 1234,
                ephemeral=False,
                single_hop=True,
            )
        self.assertIn("single_hop=", str(ctx.exception))

    def test_progress_updates_global_tor(self, ftb):
        with patch('txtorcon.endpoints.get_global_tor_instance') as tor:
            ep = TCPHiddenServiceEndpoint.global_tor(self.reactor, 1234)
            tor.call_args[1]['progress_updates'](40, 'FOO', 'foo to the bar')
            return ep

    def test_hiddenservice_key_unfound(self, ftb):
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
                return None
        ep.hiddenservice = Blam()
        self.assertEqual(ep.onion_private_key, None)
        return ep

    def test_multiple_listen(self, ftb):
        ep = TCPHiddenServiceEndpoint(self.reactor, self.config, 123)
        d0 = ep.listen(NoOpProtocolFactory())

        @defer.inlineCallbacks
        def more_listen(arg):
            yield arg.stopListening()
            ep.listen(NoOpProtocolFactory())

            defer.returnValue(arg)
            return
        d0.addBoth(more_listen)
        self.protocol.commands[0][1].callback(
            'ServiceID=blarglyfoo\nPrivateKey=bigbadkeyblob'
        )
        self.protocol.events['HS_DESC'](
            'UPLOAD blarglyfoo x x x x'
        )
        self.protocol.events['HS_DESC'](
            'UPLOADED blarglyfoo x x x x'
        )

        def check(port):
            self.assertEqual('blarglyfoo.onion', port.getHost().onion_uri)
            self.assertEqual('127.0.0.1', ep.tcp_endpoint._interface)
            self.assertEqual(len(self.config.EphemeralOnionServices), 1)
        d0.addCallback(check).addErrback(self.fail)
        return d0

    def test_multiple_disk(self, ftb):
        tmp = self.mktemp()
        os.mkdir(tmp)
        with open(os.path.join(tmp, 'hostname'), 'w') as f:
            f.write('blarglyfoo.onion')
        with open(os.path.join(tmp, 'private_key'), 'w') as f:
            f.write('some hex or something')
        ep = TCPHiddenServiceEndpoint(self.reactor, self.config, 123, hidden_service_dir=tmp)
        d0 = ep.listen(NoOpProtocolFactory())

        @defer.inlineCallbacks
        def more_listen(arg):
            yield arg.stopListening()
            ep.listen(NoOpProtocolFactory())

            defer.returnValue(arg)
            return
        d0.addBoth(more_listen)
        if True:
            self.protocol.events['HS_DESC'](
                'UPLOAD blarglyfoo x x x x'
            )
            self.protocol.events['HS_DESC'](
                'UPLOADED blarglyfoo x x x x'
            )

        def check(port):
            self.assertEqual('blarglyfoo.onion', port.getHost().onion_uri)
            self.assertEqual('some hex or something', port.getHost().onion_key)
            self.assertEqual('127.0.0.1', ep.tcp_endpoint._interface)
            self.assertEqual(len(self.config.HiddenServices), 1)
            self.assertIs(self.config.HiddenServices[0], port.onion_service)
            self.assertTrue(IOnionService.providedBy(port.getHost().onion_service))
        d0.addCallback(check).addErrback(self.fail)
        return d0

    # XXX what is this even supposed to test?
    def _test_already_bootstrapped(self, ftb):
        self.config.bootstrap()
        ep = TCPHiddenServiceEndpoint(self.reactor, self.config, 123)
        d = ep.listen(NoOpProtocolFactory())
        self.protocol.commands[0][1].callback("ServiceID=gobbledegook\nPrivateKey=seekrit")
        self.protocol.events['HS_DESC'](
            "UPLOAD gobbledegook basic somedirauth REASON=testing"
        )
        self.protocol.events['HS_DESC'](
            "UPLOADED gobbledegook basic somedirauth REASON=testing"
        )
        return d

    @defer.inlineCallbacks
    def test_explicit_data_dir(self, ftb):
        with util.TempDir() as tmp:
            d = str(tmp)
            with open(os.path.join(d, 'hostname'), 'w') as f:
                f.write('public.onion')

            ep = TCPHiddenServiceEndpoint(self.reactor, self.config, 123, d)

            # make sure listen() correctly configures our hidden-serivce
            # with the explicit directory we passed in above
            listen_d = ep.listen(NoOpProtocolFactory())
            self.protocol.events['HS_DESC'](
                "UPLOAD public basic somedirauth REASON=testing"
            )
            self.protocol.events['HS_DESC'](
                "UPLOADED public basic somedirauth REASON=testing"
            )
            yield listen_d

            self.assertEqual(1, len(self.config.HiddenServices))
            self.assertEqual(self.config.HiddenServices[0].dir, d)
            self.assertEqual(self.config.HiddenServices[0].hostname, 'public.onion')

    def test_failure(self, ftb):
        self.reactor.failures = 1
        ep = TCPHiddenServiceEndpoint(self.reactor, self.config, 123)
        d = ep.listen(NoOpProtocolFactory())
        self.config.bootstrap()
        d.addErrback(self.check_error)
        return d

    def check_error(self, failure):
        self.assertEqual(failure.type, error.CannotListenError)
        return None

    def test_parse_via_plugin(self, ftb):
        # make sure we have a valid thing from get_global_tor without
        # actually launching tor
        config = TorConfig()
        config.post_bootstrap = defer.succeed(config)
        from txtorcon import torconfig
        torconfig._global_tor_config = None
        get_global_tor(
            self.reactor,
            _tor_launcher=lambda react, config, progress_updates=None: defer.succeed(config)
        )
        ep = serverFromString(
            self.reactor,
            'onion:88:localPort=1234:hiddenServiceDir=/foo/bar'
        )
        self.assertEqual(ep.public_port, 88)
        self.assertEqual(ep.local_port, 1234)
        self.assertEqual(ep.hidden_service_dir, '/foo/bar')

    def test_parse_via_plugin_key_from_file(self, ftb):
        tmp = self.mktemp()
        os.mkdir(tmp)
        with open(os.path.join(tmp, 'some_data'), 'wb') as f:
            f.write(b'ED25519-V3:deadbeefdeadbeef\n')

        # make sure we have a valid thing from get_global_tor without
        # actually launching tor
        config = TorConfig()
        config.post_bootstrap = defer.succeed(config)
        from txtorcon import torconfig
        torconfig._global_tor_config = None
        get_global_tor(
            self.reactor,
            _tor_launcher=lambda react, config, progress_updates=None: defer.succeed(config)
        )
        ep = serverFromString(
            self.reactor,
            'onion:88:localPort=1234:privateKeyFile={}'.format(os.path.join(tmp, 'some_data')),
        )
        self.assertEqual(ep.public_port, 88)
        self.assertEqual(ep.local_port, 1234)
        self.assertEqual(ep.private_key, "ED25519-V3:deadbeefdeadbeef")

    def test_parse_via_plugin_key_from_v3_private_file(self, ftb):
        tmp = self.mktemp()
        os.mkdir(tmp)
        with open(os.path.join(tmp, 'some_data'), 'wb') as f:
            f.write(b'== ed25519v1-secret: type0 ==\x00\x00\x00H\x9e\xa6j\x0e\x98\x85\xa9\xec\xee@\x9d&\xe2\xbfe\xc9\x90\xb9\xcb\xb2g\xb0\xab\xe4\xd0\x14c\xb0\xb2\x9dX\xfa\xaa\xf8,di8\xec\xc6\x82t\xd0A\x16>u\xde\xc6&\x82\x03\x1app\x18c`T\xc3\xdc\x1a\xca')

        # make sure we have a valid thing from get_global_tor without
        # actually launching tor
        config = TorConfig()
        config.post_bootstrap = defer.succeed(config)
        from txtorcon import torconfig
        torconfig._global_tor_config = None
        get_global_tor(
            self.reactor,
            _tor_launcher=lambda react, config, progress_updates=None: defer.succeed(config)
        )
        ep = serverFromString(
            self.reactor,
            'onion:88:localPort=1234:privateKeyFile={}'.format(os.path.join(tmp, 'some_data')),
        )
        self.assertEqual(ep.public_port, 88)
        self.assertEqual(ep.local_port, 1234)
        self.assertTrue("\n" not in ep.private_key)
        self.assertEqual(
            ep.private_key,
            u"ED25519-V3:" + b2a_base64(b"H\x9e\xa6j\x0e\x98\x85\xa9\xec\xee@\x9d&\xe2\xbfe\xc9\x90\xb9\xcb\xb2g\xb0\xab\xe4\xd0\x14c\xb0\xb2\x9dX\xfa\xaa\xf8,di8\xec\xc6\x82t\xd0A\x16>u\xde\xc6&\x82\x03\x1app\x18c`T\xc3\xdc\x1a\xca").decode('ascii').strip(),
        )

    def test_parse_via_plugin_key_from_v2_private_file(self, ftb):
        tmp = self.mktemp()
        os.mkdir(tmp)
        with open(os.path.join(tmp, 'some_data'), 'w') as f:
            f.write('-----BEGIN RSA PRIVATE KEY-----\nthekeyblob\n-----END RSA PRIVATE KEY-----\n')

        # make sure we have a valid thing from get_global_tor without
        # actually launching tor
        config = TorConfig()
        config.post_bootstrap = defer.succeed(config)
        from txtorcon import torconfig
        torconfig._global_tor_config = None
        get_global_tor(
            self.reactor,
            _tor_launcher=lambda react, config, progress_updates=None: defer.succeed(config)
        )
        ep = serverFromString(
            self.reactor,
            'onion:88:localPort=1234:privateKeyFile={}'.format(os.path.join(tmp, 'some_data')),
        )
        self.assertEqual(ep.public_port, 88)
        self.assertEqual(ep.local_port, 1234)
        self.assertEqual(
            ep.private_key,
            u"RSA1024:thekeyblob",
        )

    def test_parse_via_plugin_key_from_invalid_private_file(self, ftb):
        tmp = self.mktemp()
        os.mkdir(tmp)
        with open(os.path.join(tmp, 'some_data'), 'w') as f:
            f.write('nothing to see here\n')

        # make sure we have a valid thing from get_global_tor without
        # actually launching tor
        config = TorConfig()
        config.post_bootstrap = defer.succeed(config)
        from txtorcon import torconfig
        torconfig._global_tor_config = None
        get_global_tor(
            self.reactor,
            _tor_launcher=lambda react, config, progress_updates=None: defer.succeed(config)
        )

        with self.assertRaises(ValueError):
            serverFromString(
                self.reactor,
                'onion:88:localPort=1234:privateKeyFile={}'.format(os.path.join(tmp, 'some_data')),
            )

    def test_parse_via_plugin_single_hop(self, ftb):
        tmp = self.mktemp()
        os.mkdir(tmp)
        with open(os.path.join(tmp, 'some_data'), 'wb') as f:
            f.write(b'ED25519-V3:deadbeefdeadbeef\n')

        # make sure we have a valid thing from get_global_tor without
        # actually launching tor
        config = TorConfig()
        config.post_bootstrap = defer.succeed(config)
        from txtorcon import torconfig
        torconfig._global_tor_config = None
        get_global_tor(
            self.reactor,
            _tor_launcher=lambda react, config, progress_updates=None: defer.succeed(config)
        )
        ep = serverFromString(
            self.reactor,
            'onion:88:localPort=1234:singleHop=True:privateKeyFile={}'.format(os.path.join(tmp, 'some_data')),
        )
        self.assertEqual(ep.public_port, 88)
        self.assertEqual(ep.local_port, 1234)
        self.assertEqual(ep.private_key, "ED25519-V3:deadbeefdeadbeef")
        self.assertTrue(ep.single_hop)

    def test_parse_via_plugin_single_hop_explicit_false(self, ftb):
        tmp = self.mktemp()
        os.mkdir(tmp)
        with open(os.path.join(tmp, 'some_data'), 'wb') as f:
            f.write(b'ED25519-V3:deadbeefdeadbeef\n')

        # make sure we have a valid thing from get_global_tor without
        # actually launching tor
        config = TorConfig()
        config.post_bootstrap = defer.succeed(config)
        from txtorcon import torconfig
        torconfig._global_tor_config = None
        get_global_tor(
            self.reactor,
            _tor_launcher=lambda react, config, progress_updates=None: defer.succeed(config)
        )
        ep = serverFromString(
            self.reactor,
            'onion:88:localPort=1234:singleHop=false:privateKeyFile={}'.format(os.path.join(tmp, 'some_data')),
        )
        self.assertEqual(ep.public_port, 88)
        self.assertEqual(ep.local_port, 1234)
        self.assertEqual(ep.private_key, "ED25519-V3:deadbeefdeadbeef")
        self.assertFalse(ep.single_hop)

    def test_parse_via_plugin_single_hop_bogus(self, ftb):
        with self.assertRaises(ValueError):
            serverFromString(
                self.reactor,
                'onion:88:singleHop=yes_please',
            )

    def test_parse_via_plugin_key_and_keyfile(self, ftb):
        with self.assertRaises(ValueError):
            serverFromString(
                self.reactor,
                'onion:88:privateKeyFile=foo:privateKey=blarg'
            )

    def test_parse_via_plugin_key_and_dir(self, ftb):
        with self.assertRaises(ValueError):
            serverFromString(
                self.reactor,
                'onion:88:localPort=1234:hiddenServiceDir=/foo/bar:privateKey=blarg'
            )

    def test_parse_illegal_version_foo(self, ftb):
        with self.assertRaises(ValueError) as ctx:
            serverFromString(
                self.reactor,
                'onion:88:version=foo:localPort=1234:hiddenServiceDir=~/blam/blarg'
            )
        self.assertIn(
            "version must be an int",
            str(ctx.exception),
        )

    def test_parse_illegal_version_1(self, ftb):
        with self.assertRaises(ValueError) as ctx:
            serverFromString(
                self.reactor,
                'onion:88:version=1:localPort=1234:hiddenServiceDir=~/blam/blarg'
            )
        self.assertIn(
            "Invalid version '1'",
            str(ctx.exception),
        )

    def test_parse_version_3(self, ftb):
        ep = serverFromString(
            self.reactor,
            'onion:88:version=3:localPort=1234:hiddenServiceDir=~/blam/blarg'
        )
        self.assertFalse(ep.ephemeral)

    def test_parse_user_path(self, ftb):
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
            _tor_launcher=lambda react, config, progress_updates=None: defer.succeed(config)
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

    def test_parse_relative_path(self, ftb):
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
            _tor_launcher=lambda react, config, progress_updates=None: defer.succeed(config)
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

    def test_illegal_arg_ephemeral_auth(self, ftb):
        # XXX I think Tor does actually support this now?
        reactor = Mock()
        config = Mock()
        with self.assertRaises(ValueError) as ctx:
            TCPHiddenServiceEndpoint(
                reactor, config, 80,
                stealth_auth=['alice', 'bob'],
                ephemeral=True,
            )
        self.assertIn(
            "onion services don't support 'stealth' auth",
            str(ctx.exception),
        )

    def test_illegal_arg_ephemeral_hsdir(self, ftb):
        reactor = Mock()
        config = Mock()
        with self.assertRaises(ValueError) as ctx:
            TCPHiddenServiceEndpoint(
                reactor, config, 80,
                ephemeral=True,
                hidden_service_dir='/tmp/foo',
            )
        self.assertIn(
            "Specifying 'hidden_service_dir' is incompatible",
            str(ctx.exception),
        )

    def test_illegal_arg_disk_privkey(self, ftb):
        reactor = Mock()
        config = Mock()
        with self.assertRaises(ValueError) as ctx:
            TCPHiddenServiceEndpoint(
                reactor, config, 80,
                ephemeral=False,
                private_key=b'something',
            )
        self.assertIn(
            "only understood for ephemeral services",
            str(ctx.exception),
        )

    @defer.inlineCallbacks
    def test_illegal_arg_torconfig(self, ftb):

        class Foo(object):
            pass
        config = Foo()

        ep = TCPHiddenServiceEndpoint(self.reactor, config, 123)
        factory = Mock()
        with self.assertRaises(ValueError) as ctx:
            yield ep.listen(factory)

        self.assertIn(
            "Expected a TorConfig instance but",
            str(ctx.exception)
        )

    @skipIf('pypy' in sys.version.lower(), "Weird OpenSSL+PyPy problem on Travis")
    @defer.inlineCallbacks
    def test_basic_auth_ephemeral(self, ftb):
        '''
        '''
        ep = TCPHiddenServiceEndpoint(
            self.reactor, self.config, 123,
            ephemeral=True,
            auth=AuthBasic(['alice', 'bob']),
            private_key=_test_private_key_blob,
        )

        # make sure listen() correctly configures our hidden-serivce
        # with the explicit directory we passed in above
        d = ep.listen(NoOpProtocolFactory())

        self.assertEqual(1, len(self.protocol.commands))
        cmd, cmd_d = self.protocol.commands[0]
        self.assertTrue(
            cmd.startswith(u"ADD_ONION RSA1024:{} ".format(_test_private_key_blob))
        )
        cmd_d.callback("ServiceID={}\nPrivateKey={}\nClientAuth=bob:asdf\nClientAuth=alice:fdsa\n".format(_test_onion_id, _test_private_key_blob))

        self.protocol.events['HS_DESC'](
            "UPLOAD {} basic somedirauth REASON=testing".format(_test_onion_id)
        )
        self.protocol.events['HS_DESC'](
            "UPLOADED {} basic somedirauth REASON=testing".format(_test_onion_id)
        )

        yield d  # returns 'port'
        self.assertEqual(1, len(self.config.EphemeralOnionServices))
        service = self.config.EphemeralOnionServices[0]
        self.assertTrue(IAuthenticatedOnionClients.providedBy(service))
        self.assertEqual(
            set(["alice", "bob"]),
            set(service.client_names()),
        )
        self.assertEqual(
            "asdf",
            service.get_client("bob").auth_token,
        )
        self.assertEqual(
            "fdsa",
            service.get_client("alice").auth_token,
        )

    @defer.inlineCallbacks
    def test_basic_ephemeral_v3(self, ftb):
        '''
        '''
        ep = TCPHiddenServiceEndpoint(
            self.reactor, self.config, 123,
            ephemeral=True,
            version=3,
            private_key='f' * 32,
        )

        # make sure listen() correctly configures our hidden-serivce
        # with the explicit directory we passed in above
        d = ep.listen(NoOpProtocolFactory())

        self.assertEqual(1, len(self.protocol.commands))
        cmd, cmd_d = self.protocol.commands[0]
        self.assertTrue(
            cmd.startswith(u"ADD_ONION ED25519-V3:ffffffffffffffffffffffffffffffff ")
        )
        cmd_d.callback("ServiceID=service\nPrivateKey=deadbeef")

        self.protocol.events['HS_DESC'](
            "UPLOAD service basic somedirauth REASON=testing"
        )
        self.protocol.events['HS_DESC'](
            "UPLOADED service basic somedirauth REASON=testing"
        )

        yield d  # returns 'port'
        self.assertEqual(1, len(self.config.EphemeralOnionServices))
        service = self.config.EphemeralOnionServices[0]
        self.assertTrue(IOnionService.providedBy(service))

    @defer.inlineCallbacks
    def test_stealth_auth(self, ftb):
        '''
        make sure we produce a HiddenService instance with stealth-auth
        lines if we had authentication specified in the first place.
        '''
        tmp = self.mktemp()
        os.mkdir(tmp)
        with open(os.path.join(tmp, 'hostname'), 'w') as f:
            f.write('public0.onion token0 # client: alice\n')
            f.write('public1.onion token1 # client: bob\n')
        with open(os.path.join(tmp, 'private_key'), 'w') as f:
            f.write(_test_private_key)

        ep = TCPHiddenServiceEndpoint(
            self.reactor, self.config, 123, tmp,
            stealth_auth=['alice', 'bob'],
        )

        # make sure listen() correctly configures our hidden-serivce
        # with the explicit directory we passed in above
        d = ep.listen(NoOpProtocolFactory())

        def foo(fail):
            return fail
        d.addErrback(foo)

        self.protocol.events['HS_DESC'](
            "UPLOAD {} basic somedirauth REASON=testing".format(_test_onion_id)
        )
        self.protocol.events['HS_DESC'](
            "UPLOADED {} basic somedirauth REASON=testing".format(_test_onion_id)
        )

        port = yield d  # returns 'port'
        self.assertEqual(1, len(self.config.HiddenServices))

        hs = self.config.HiddenServices[0]
        # hs will be IAuthenticatedOnionService
        self.assertEqual(2, len(hs.client_names()))
        self.assertIn("alice", hs.client_names())
        self.assertIn("bob", hs.client_names())

        alice = hs.get_client("alice")
        self.assertEqual(alice.hidden_service_directory, os.path.abspath(tmp))
        self.assertEqual("token0", alice.auth_token)

        with self.assertRaises(ValueError):
            ep.onion_uri
        hs = port.onion_service
        self.assertEqual('public0.onion', hs.get_client("alice").hostname)
        self.assertEqual('public1.onion', hs.get_client("bob").hostname)

    def test_stealth_auth_deprecated(self, ftb):
        '''
        make sure we produce a HiddenService instance with stealth-auth
        lines if we had authentication specified in the first place.
        '''
        tmp = self.mktemp()
        os.mkdir(tmp)
        with open(os.path.join(tmp, 'hostname'), 'w') as f:
            f.write('public.onion\n')

        with self.assertRaises(ValueError) as ctx:
            TCPHiddenServiceEndpoint(
                self.reactor, self.config, 123, tmp,
                stealth_auth=['alice', 'bob'],
                auth=AuthStealth(['alice', 'bob']),
            )
        self.assertIn(
            "use auth= only for new code",
            str(ctx.exception),
        )

    @defer.inlineCallbacks
    def test_factory(self, ftb):
        reactor = Mock()
        cp = Mock()
        cp.get_conf = Mock(return_value=defer.succeed(dict()))

        with patch(u'txtorcon.endpoints.available_tcp_port', return_value=9999):
            ep = yield TorClientEndpoint.from_connection(reactor, cp, 'localhost', 1234)

        self.assertTrue(isinstance(ep, TorClientEndpoint))
        self.assertEqual(ep.host, 'localhost')
        self.assertEqual(ep.port, 1234)


class EndpointLaunchTests(unittest.TestCase):

    def setUp(self):
        self.reactor = FakeReactorTcp(self)
        self.protocol = FakeControlProtocol([])

    def test_onion_address(self):
        hs = Mock()
        hs.hostname = "foo.onion"
        addr = TorOnionAddress(80, hs)
        # just want to run these and assure they don't throw
        # exceptions.
        repr(addr)
        hash(addr)

    def test_onion_parse_unix_socket(self):
        r = proto_helpers.MemoryReactor()
        serverFromString(r, "onion:80:controlPort=/tmp/foo")

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
        yield ep.listen(NoOpProtocolFactory())
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
        yield ep.listen(NoOpProtocolFactory())
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


@implementer(IReactorTCP, IReactorCore)
class FakeReactorTcp(object):

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
    def __init__(self, host, port, method, factory):
        self.host = host
        self.port = port
        self.method = method
        self.factory = factory
        self._done = SingleObserver()

    def when_done(self):
        return self._done.when_fired()

    def makeConnection(self, transport):
        proto = self.factory.buildProtocol('socks5 addr')
        self._done.fire(proto)


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
        target._get_address = Mock(return_value=defer.succeed(src_addr))
        stream = Mock()
        stream.source_port = 1234
        stream.source_addr = 'host'

        # okay, so we fire up our circuit-endpoint with mostly mocked
        # things, and a circuit that's already in 'FAILED' state.
        ep = TorCircuitEndpoint(reactor, torstate, circ, target)

        # should get a Failure from the connect()
        d = ep.connect(Mock())
        attacher = yield _get_circuit_attacher(reactor, Mock())
        attacher.attach_stream(stream, [circ])
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
        target._get_address = Mock(return_value=defer.succeed(src_addr))
        stream = Mock()
        stream.source_port = 1234
        stream.source_addr = 'host'

        # okay, so we fire up our circuit-endpoint with mostly mocked
        # things, and a circuit that's already in 'FAILED' state.
        ep = TorCircuitEndpoint(reactor, torstate, circ, target)

        # should get a Failure from the connect()
        d = ep.connect(Mock())
        attacher = yield _get_circuit_attacher(reactor, Mock())
        attacher.attach_stream_failure(stream, RuntimeError("a bad thing"))
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
        target._get_address = Mock(return_value=defer.succeed(src_addr))
        stream = Mock()
        stream.source_port = 1234
        stream.source_addr = 'host'

        # okay, so we fire up our circuit-endpoint with mostly mocked
        # things, and a circuit that's already in 'FAILED' state.
        ep = TorCircuitEndpoint(reactor, torstate, circ, target)

        # should get a Failure from the connect()
        d = ep.connect(Mock())
        attacher = yield _get_circuit_attacher(reactor, torstate)
        yield attacher.attach_stream(stream, [circ])
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
        endpoint = TorClientEndpoint(
            '', 0,
            socks_endpoint=tor_endpoint,
        )
        d = endpoint.connect(None)
        return self.assertFailure(d, ConnectionRefusedError)

    def test_client_connection_failed_user_password(self):
        """
        Same as above, but with a username/password.
        """
        tor_endpoint = FakeTorSocksEndpoint(
            None, "fakehose", 9050,
            failure=Failure(ConnectionRefusedError()),
        )
        endpoint = TorClientEndpoint(
            'invalid host', 0,
            socks_username='billy', socks_password='s333cure',
            socks_endpoint=tor_endpoint)
        d = endpoint.connect(None)
        # XXX we haven't fixed socks.py to support user/pw yet ...
        return self.assertFailure(d, RuntimeError)
        return self.assertFailure(d, ConnectionRefusedError)

    def test_no_host(self):
        self.assertRaises(
            ValueError,
            TorClientEndpoint, None, None, Mock(),
        )

    def test_parser_basic(self):
        ep = clientFromString(None, 'tor:host=timaq4ygg2iegci7.onion:port=80:socksPort=9050')

        self.assertEqual(ep.host, 'timaq4ygg2iegci7.onion')
        self.assertEqual(ep.port, 80)
        # XXX what's "the Twisted way" to get the port out here?
        self.assertEqual(ep._socks_endpoint._port, 9050)

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
        This test is equivalent to txsocksx's
        TestSOCKS5ClientEndpoint.test_defaultFactory
        """

        tor_endpoint = FakeTorSocksEndpoint(None, "fakehost", 9050)
        endpoint = TorClientEndpoint(
            '', 0,
            socks_endpoint=tor_endpoint,
        )
        endpoint.connect(Mock)
        self.assertEqual(tor_endpoint.transport.value(), b'\x05\x01\x00')

    @defer.inlineCallbacks
    def test_success(self):
        with patch.object(_TorSocksFactory, "protocol", FakeSocksProto):
            tor_endpoint = FakeTorSocksEndpoint(Mock(), "fakehost", 9050)
            endpoint = TorClientEndpoint(
                u'meejah.ca', 443,
                socks_endpoint=tor_endpoint,
            )
            proto = yield endpoint.connect(MagicMock())
            self.assertTrue(isinstance(proto, FakeSocksProto))
            self.assertEqual(u"meejah.ca", proto.host)
            self.assertEqual(443, proto.port)
            self.assertEqual('CONNECT', proto.method)

    def test_good_port_retry(self):
        """
        This tests that our Tor client endpoint retry logic works correctly.
        We create a proxy endpoint that fires a ConnectionRefusedError
        unless the connecting port matches. We attempt to connect with the
        proxy endpoint for each port that the Tor client endpoint will try.
        """
        success_ports = TorClientEndpoint.socks_ports_to_try
        for port in success_ports:
            tor_endpoint = FakeTorSocksEndpoint(
                u"fakehost", "127.0.0.1", port,
                accept_port=port,
                failure=Failure(ConnectionRefusedError()),
            )

            endpoint = TorClientEndpoint(
                '', 0,
                socks_endpoint=tor_endpoint,
            )
            endpoint.connect(Mock())
            self.assertEqual(tor_endpoint.transport.value(), b'\x05\x01\x00')

    def test_bad_port_retry(self):
        """
        This tests failure to connect to the ports on the "try" list.
        """
        fail_ports = [1984, 666]
        for port in fail_ports:
            ep = FakeTorSocksEndpoint(
                '', '', 0,
                accept_port=port,
                failure=Failure(ConnectionRefusedError()),
            )
            endpoint = TorClientEndpoint('', 0, socks_endpoint=ep)
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

            def _get_address(self):
                return defer.succeed(None)

        ep_mock.side_effect = FakeSocks5
        endpoint = TorClientEndpoint('', 0)
        d = endpoint.connect(Mock())
        self.assertFailure(d, ConnectionRefusedError)

    @patch('txtorcon.endpoints.TorSocksEndpoint')
    @defer.inlineCallbacks
    def test_default_socks_ports_happy(self, ep_mock):
        """
        Ensure we iterate over the default socks ports
        """

        proto = object()
        ports_attempted = []

        class FakeSocks5(object):

            def __init__(self, tor_ep, *args, **kw):
                self.tor_port = tor_ep._port

            def connect(self, *args, **kw):
                ports_attempted.append(self.tor_port)
                if self.tor_port != 9150:
                    return Failure(error.ConnectError("foo"))
                else:
                    return proto

            def _get_address(self):
                return defer.succeed(None)

        ep_mock.side_effect = FakeSocks5
        endpoint = TorClientEndpoint('', 0)
        p2 = yield endpoint.connect(None)
        self.assertTrue(proto is p2)
        self.assertEqual(
            ports_attempted,
            [9050, 9150]
        )

        # now, if we re-use the endpoint, we should again attempt the
        # two ports
        p3 = yield endpoint.connect(None)
        self.assertTrue(proto is p3)
        self.assertEqual(
            ports_attempted,
            [9050, 9150, 9050, 9150]
        )

    @patch('txtorcon.endpoints.TorSocksEndpoint')
    @defer.inlineCallbacks
    def test_tls_socks_no_endpoint(self, ep_mock):
        the_proto = object()
        proto = defer.succeed(the_proto)

        class FakeSocks5(object):

            def __init__(self, *args, **kw):
                pass

            def connect(self, *args, **kw):
                return proto

            def _get_address(self):
                return defer.succeed(None)

        ep_mock.side_effect = FakeSocks5
        endpoint = TorClientEndpoint('torproject.org', 0, tls=True)
        p2 = yield endpoint.connect(None)
        self.assertTrue(the_proto is p2)

    @patch('txtorcon.endpoints.TorSocksEndpoint')
    @defer.inlineCallbacks
    def test_tls_socks_with_endpoint(self, ep_mock):
        """
        Same as above, except we provide an explicit endpoint
        """
        the_proto = object()
        proto_d = defer.succeed(the_proto)

        class FakeSocks5(object):

            def __init__(self, *args, **kw):
                pass

            def connect(self, *args, **kw):
                return proto_d

            def _get_address(self):
                return defer.succeed(None)

        ep_mock.side_effect = FakeSocks5
        endpoint = TorClientEndpoint(
            u'torproject.org', 0,
            socks_endpoint=clientFromString(Mock(), "tcp:localhost:9050"),
            tls=True,
        )
        p2 = yield endpoint.connect(None)
        self.assertTrue(p2 is the_proto)

    def test_client_endpoint_old_api(self):
        """
        Test the old API of passing socks_host, socks_port
        """

        reactor = Mock()
        directlyProvides(reactor, IReactorCore)
        endpoint = TorClientEndpoint(
            'torproject.org', 0,
            socks_hostname='localhost',
            socks_port=9050,
            reactor=reactor,
        )
        self.assertTrue(
            isinstance(endpoint._socks_endpoint, TCP4ClientEndpoint)
        )

        endpoint.connect(Mock())
        calls = reactor.mock_calls
        self.assertEqual(1, len(calls))
        name, args, kw = calls[0]
        self.assertEqual("connectTCP", name)
        self.assertEqual("localhost", args[0])
        self.assertEqual(9050, args[1])

    def test_client_endpoint_get_address(self):
        """
        Test the old API of passing socks_host, socks_port
        """

        reactor = FakeReactorTcp(self)
        endpoint = TorClientEndpoint(
            'torproject.org', 0,
            socks_endpoint=clientFromString(Mock(), "tcp:localhost:9050"),
            reactor=reactor,
        )
        d = endpoint._get_address()
        self.assertTrue(not d.called)


class TestSocksFactory(unittest.TestCase):

    @defer.inlineCallbacks
    def test_explicit_socks(self):
        reactor = Mock()
        cp = Mock()
        cp.get_conf = Mock(
            return_value=defer.succeed({
                'SocksPort': ['9050', '9150', 'unix:/tmp/boom']
            })
        )

        ep = yield _create_socks_endpoint(reactor, cp, socks_config='unix:/tmp/boom')

        self.assertTrue(isinstance(ep, UNIXClientEndpoint))

    @defer.inlineCallbacks
    def test_unix_socket_with_options(self):
        reactor = Mock()
        cp = Mock()
        cp.get_conf = Mock(
            return_value=defer.succeed({
                'SocksPort': ['unix:/tmp/boom SomeOption']
            })
        )

        ep = yield _create_socks_endpoint(reactor, cp)

        self.assertTrue(isinstance(ep, UNIXClientEndpoint))
        self.assertEqual("/tmp/boom", ep._path)

    @defer.inlineCallbacks
    def test_unix_socket_bad(self):
        reactor = Mock()
        cp = Mock()
        cp.get_conf = Mock(
            return_value=defer.succeed({
                'SocksPort': ['unix:bad worse wosrt']
            })
        )
        the_error = Exception("a bad thing")

        def boom(*args, **kw):
            raise the_error

        with patch('txtorcon.endpoints.available_tcp_port', lambda r: 1234):
            with patch('txtorcon.torconfig.UNIXClientEndpoint', boom):
                yield _create_socks_endpoint(reactor, cp)
        errs = self.flushLoggedErrors()
        self.assertEqual(errs[0].value, the_error)

    @defer.inlineCallbacks
    def test_nothing_exists(self):
        reactor = Mock()
        cp = Mock()
        cp.get_conf = Mock(return_value=defer.succeed(dict()))

        with patch(u'txtorcon.endpoints.available_tcp_port', return_value=9999):
            ep = yield _create_socks_endpoint(reactor, cp)

        self.assertTrue(isinstance(ep, TCP4ClientEndpoint))
        # internal details, but ...
        self.assertEqual(ep._port, 9999)
