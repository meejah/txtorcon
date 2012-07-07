from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.internet import defer
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet.interfaces import IProtocolFactory
from zope.interface import implements

from txtorcon.util import process_from_address, delete_file_or_tree

import os
import tempfile
import subprocess

class FakeState:
    tor_pid = 0

class FakeProtocolFactory:
    implements(IProtocolFactory)
    def doStart(self):
        "IProtocolFactory API"

    def doStop(self):
        "IProtocolFactory API"
        
    def buildProtocol(self, addr):
        "IProtocolFactory API"
        return None

class TestProcessFromUtil(unittest.TestCase):

    def setUp(self):
        self.fakestate = FakeState()

    def test_none(self):
        self.assertEqual(process_from_address(None, 80, self.fakestate), None)

    def test_internal(self):
        pfa = process_from_address('(Tor_internal)', 80, self.fakestate)
        # depends on whether you have psutil installed or not, and on
        # whether your system always has a PID 0 process...
        self.assertEqual(pfa, self.fakestate.tor_pid)

    @defer.inlineCallbacks
    def test_real_addr(self):
        ## FIXME should choose a port which definitely isn't used.

        ## it's apparently frowned upon to use the "real" reactor in
        ## tests, but I was using "nc" before, and I think this is
        ## preferable.
        from twisted.internet import reactor
        listener = yield TCP4ServerEndpoint(reactor, 9887).listen(FakeProtocolFactory())
        
        try:
            pid = process_from_address('0.0.0.0', 9887, self.fakestate)
        finally:
            listener.stopListening()

        self.assertEqual(pid, os.getpid())

class TestDelete(unittest.TestCase):

    def test_delete_file(self):
        (fd, f) = tempfile.mkstemp()
        os.write(fd, 'some\ndata\n')
        os.close(fd)
        self.assertTrue(os.path.exists(f))
        delete_file_or_tree(f)
        self.assertTrue(not os.path.exists(f))

    def test_delete_tree(self):
        d = tempfile.mkdtemp()
        f = open(os.path.join(d, 'foo'), 'w')
        f.write('foo\n')
        f.close()

        self.assertTrue(os.path.exists(d))
        self.assertTrue(os.path.isdir(d))
        self.assertTrue(os.path.exists(os.path.join(d,'foo')))
        
        delete_file_or_tree(d)
        
        self.assertTrue(not os.path.exists(d))
        self.assertTrue(not os.path.exists(os.path.join(d,'foo')))

