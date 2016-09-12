
from zope.interface.verify import verifyClass, verifyObject
from zope.interface import implementer

from mock import Mock

from twisted.trial import unittest

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

