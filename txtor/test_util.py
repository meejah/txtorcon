from twisted.trial import unittest
from twisted.test import proto_helpers

from txtor.util import process_from_address, delete_file_or_tree

import os
import tempfile
import subprocess

class FakeState:
    tor_pid = -1

class TestProcessFromUtil(unittest.TestCase):

    def setUp(self):
        self.fakestate = FakeState()

    def test_none(self):
        self.assertTrue(process_from_address(None, 80, self.fakestate) == None)

    def test_internal(self):
        self.assertTrue(process_from_address('(Tor_internal)', 80, self.fakestate) == self.fakestate.tor_pid)

    def test_real_addr(self):
        ## FIXME should choose a port which definitely isn't used.
        proc = subprocess.Popen(['nc', '-l', '127.0.0.1', '9887'], env={})
        pid = process_from_address('127.0.0.1', 9887, self.fakestate)
        self.assertTrue(pid == proc.pid)
        proc.terminate()

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

