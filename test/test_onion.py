
from zope.interface.verify import verifyClass, verifyObject
from zope.interface import implementer

from mock import Mock

from twisted.trial import unittest
from twisted.internet import defer

from txtorcon.onion import EphemeralHiddenService
from txtorcon.onion import IOnionService  # FIXME interfaces.py


class OnionInterfaceTests(unittest.TestCase):
    def test_ephemeral_class(self):
        # as far as I can tell, this is worthless? just seems to check
        # that there's an @implemeter(IOnionService) on the class
        # (i.e. doesn't verify an Attribute, anyway...)
        verifyClass(IOnionService, EphemeralHiddenService)

    def test_ephemeral_obj(self):
        verifyObject(
            IOnionService,
            EphemeralHiddenService(Mock(), [])
        )


class EphemeralServiceTests(unittest.TestCase):

    @defer.inlineCallbacks
    def test_uploads_fail(self):
        """
        When all descriptor uploads fail, we get an error
        """

        class FakeProtocol(object):
            listener = None

            def queue_command(s, cmd):
                return "ServiceID=deadbeefdeadbeef\nPrivateKey=RSA1024:xxxx"

            def add_event_listener(s, evt, listener):
                self.assertTrue(evt == 'HS_DESC')
                # should only get one listener added
                self.assertTrue(s.listener is None)
                s.listener = listener

        class FakeConfig(object):
            EphemeralOnionServices=[]
            tor_protocol = FakeProtocol()

        progress = Mock()
        config = FakeConfig()
        hs = EphemeralHiddenService.create(
            config,
            ['80 127.0.0.1:80'],
            progress=progress,
        )

        for x in range(6):
            config.tor_protocol.listener('UPLOAD deadbeefdeadbeef x hs_dir_{}'.format(x))

        for x in range(6):
            config.tor_protocol.listener('FAILED deadbeefdeadbeef x hs_dir_{}'.format(x))

        try:
            hs = yield hs
            self.fail("should have gotten exception")
        except Exception as e:
            self.assertTrue("Failed to upload 'deadbeefdeadbeef.onion'" in str(e))
            for x in range(6):
                self.assertTrue("hs_dir_{}".format(x) in str(e))
