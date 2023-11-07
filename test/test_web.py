
from unittest.mock import Mock

from twisted.web.client import BrowserLikePolicyForHTTPS
from twisted.trial import unittest
from twisted.internet import defer

try:
    from txtorcon.web import agent_for_socks_port
    from txtorcon.web import tor_agent
    _HAVE_WEB = True
except ImportError:
    _HAVE_WEB = False
from txtorcon.socks import TorSocksEndpoint
from txtorcon.circuit import TorCircuitEndpoint


class CustomTLSContextFactory(BrowserLikePolicyForHTTPS):
    def creatorForNetloc(self, hostname, port):
        return super().creatorForNetloc(b"custom.domain", port)


class WebAgentTests(unittest.TestCase):
    if not _HAVE_WEB:
        skip = "Missing web"

    def test_socks_agent_tcp_port(self):
        reactor = Mock()
        config = Mock()
        config.SocksPort = ['1234']
        agent_for_socks_port(reactor, config, '1234')

    @defer.inlineCallbacks
    def test_socks_agent_error_saving(self):
        reactor = Mock()
        config = Mock()
        config.SocksPort = []

        def boom(*args, **kw):
            raise RuntimeError("sad times at ridgemont high")
        config.save = boom
        try:
            yield agent_for_socks_port(reactor, config, '1234')
            self.fail("Should get an error")
        except RuntimeError as e:
            self.assertTrue("sad times at ridgemont high" in str(e))

    def test_socks_agent_unix(self):
        reactor = Mock()
        config = Mock()
        config.SocksPort = []
        agent_for_socks_port(reactor, config, 'unix:/foo')

    @defer.inlineCallbacks
    def test_socks_agent_tcp_host_port(self):
        reactor = Mock()
        config = Mock()
        config.SocksPort = []
        proto = Mock()
        gold = object()
        proto.request = Mock(return_value=defer.succeed(gold))

        def getConnection(key, endpoint):
            self.assertTrue(isinstance(endpoint, TorSocksEndpoint))
            self.assertIsInstance(
                endpoint._tls,
                BrowserLikePolicyForHTTPS().creatorForNetloc(b"host", 443).__class__
            )
            # This uses a Twisted private interface...
            self.assertEqual(endpoint._tls._hostname, "meejah.ca")
            self.assertEqual(endpoint._host, u'meejah.ca')
            self.assertEqual(endpoint._port, 443)
            return defer.succeed(proto)
        pool = Mock()
        pool.getConnection = getConnection

        # do the test
        agent = yield agent_for_socks_port(reactor, config, '127.0.0.50:1234', pool=pool)

        # apart from the getConnection asserts...
        res = yield agent.request(b'GET', b'https://meejah.ca')
        self.assertIs(res, gold)

    @defer.inlineCallbacks
    def test_socks_agent_custom_tls_context_factory(self):
        reactor = Mock()
        config = Mock()
        config.SocksPort = []
        proto = Mock()
        gold = object()
        proto.request = Mock(return_value=defer.succeed(gold))

        def getConnection(key, endpoint):

            self.assertIsInstance(
                endpoint._tls,
                BrowserLikePolicyForHTTPS().creatorForNetloc(b"host", 443).__class__
            )
            # This uses a Twisted private interface...
            self.assertEqual(endpoint._tls._hostname, "custom.domain")
            self.assertEqual(endpoint._host, 'meejah.ca')
            return defer.succeed(proto)
        pool = Mock()
        pool.getConnection = getConnection

        # do the test
        agent = yield agent_for_socks_port(
            reactor, config, '127.0.0.50:1234', pool=pool,
            tls_context_factory=CustomTLSContextFactory()
        )

        # apart from the getConnection asserts...
        res = yield agent.request(b'GET', b'https://meejah.ca')
        self.assertIs(res, gold)

    @defer.inlineCallbacks
    def test_agent(self):
        reactor = Mock()
        socks_ep = Mock()
        yield tor_agent(reactor, socks_ep)

    @defer.inlineCallbacks
    def test_agent_no_socks(self):
        reactor = Mock()
        with self.assertRaises(Exception) as ctx:
            yield tor_agent(reactor, None)
        self.assertTrue('Must provide socks_endpoint' in str(ctx.exception))

    @defer.inlineCallbacks
    def test_agent_with_circuit(self):
        reactor = Mock()
        circuit = Mock()
        socks_ep = Mock()
        proto = Mock()
        gold = object()
        proto.request = Mock(return_value=defer.succeed(gold))

        def getConnection(key, endpoint):
            self.assertTrue(isinstance(endpoint, TorCircuitEndpoint))
            target = endpoint._target_endpoint
            self.assertIsInstance(
                target._tls,
                BrowserLikePolicyForHTTPS().creatorForNetloc(b"host", 443).__class__
            )
            # This uses a Twisted private interface...
            self.assertEqual(target._tls._hostname, "meejah.ca")
            self.assertEqual(target._host, u'meejah.ca')
            self.assertEqual(target._port, 443)
            return defer.succeed(proto)
        pool = Mock()
        pool.getConnection = getConnection

        agent = yield tor_agent(reactor, socks_ep, circuit=circuit, pool=pool)

        # apart from the getConnection asserts...
        res = yield agent.request(b'GET', b'https://meejah.ca')
        self.assertIs(res, gold)

    @defer.inlineCallbacks
    def test_agent_with_circuit_tls_context_factory(self):
        reactor = Mock()
        circuit = Mock()
        socks_ep = Mock()
        proto = Mock()
        gold = object()
        proto.request = Mock(return_value=defer.succeed(gold))

        def getConnection(key, endpoint):
            target = endpoint._target_endpoint
            self.assertIsInstance(
                target._tls,
                BrowserLikePolicyForHTTPS().creatorForNetloc(b"host", 443).__class__
            )
            # This uses a Twisted private interface...
            self.assertEqual(target._tls._hostname, "custom.domain")
            self.assertEqual(target._host, 'meejah.ca')
            return defer.succeed(proto)
        pool = Mock()
        pool.getConnection = getConnection

        agent = yield tor_agent(
            reactor, socks_ep, circuit=circuit, pool=pool,
            tls_context_factory=CustomTLSContextFactory()
        )

        # apart from the getConnection asserts...
        res = yield agent.request(b'GET', b'https://meejah.ca')
        self.assertIs(res, gold)
