
from mock import Mock

from twisted.trial import unittest
from twisted.internet import defer

from txtorcon.web import agent_for_socks_port
from txtorcon.socks import TorSocksEndpoint


class WebAgentTests(unittest.TestCase):

    def test_socks_agent_tcp_port(self):
        reactor = Mock()
        config = Mock()
        config.SocksPort = ['1234']
        agent = agent_for_socks_port(reactor, config, '1234')

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
            self.assertTrue(endpoint._tls)
            self.assertEqual(endpoint._host, 'meejah.ca')
            self.assertEqual(endpoint._port, 443)
            return defer.succeed(proto)
        pool = Mock()
        pool.getConnection = getConnection

        # do the test
        agent = yield agent_for_socks_port(reactor, config, '127.0.0.50:1234', pool=pool)

        # apart from the getConnection asserts...
        res = yield agent.request(b'GET', b'https://meejah.ca')
        self.assertIs(res, gold)

        
    def test_socks_agent_unix(self):
        reactor = Mock()
        config = Mock()
        config.SocksPort = []
        agent = agent_for_socks_port(reactor, config, 'unix:/foo')
        
