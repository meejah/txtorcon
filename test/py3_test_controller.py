from mock import Mock

from twisted.trial import unittest
from twisted.internet.defer import ensureDeferred
from zope.interface import directlyProvides

from txtorcon import TorConfig
from txtorcon.interface import ITorControlProtocol
from txtorcon.controller import Tor


class ClientOnionServiceAuthenticationTests3(unittest.TestCase):

    def setUp(self):
        reactor = Mock()
        proto = Mock()
        directlyProvides(proto, ITorControlProtocol)
        self.cfg = TorConfig()
        self.cfg.HidServAuth = ["existing.onion some_token"]
        self.tor = Tor(reactor, proto, _tor_config=self.cfg)

    def test_context(self):
        return ensureDeferred(self._context_test())

    async def _context_test(self):
        async with self.tor.onion_authentication("some.onion", "token"):
            self.assertIn("some.onion token", self.cfg.HidServAuth)
        self.assertNotIn("some.onion token", self.cfg.HidServAuth)
        self.assertIn("existing.onion some_token", self.cfg.HidServAuth)
