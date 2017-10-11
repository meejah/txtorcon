from __future__ import print_function

import os
import shutil
import tempfile
import functools
from six import StringIO
from mock import Mock, patch
from os.path import join

from zope.interface import implementer, directlyProvides
from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.internet import defer
from twisted.internet.interfaces import IReactorCore
from twisted.python.failure import Failure

from txtorcon import TorProtocolError
from txtorcon import ITorControlProtocol
from txtorcon import TorProcessProtocol
from txtorcon import TorConfig
from txtorcon import DEFAULT_VALUE
from txtorcon import HiddenService
from txtorcon import launch
from txtorcon import TorNotFound
from txtorcon import torconfig

from txtorcon.torconfig import parse_client_keys
from txtorcon.torconfig import CommaList
from txtorcon.torconfig import launch_tor
from txtorcon.onion import FilesystemOnionService
from txtorcon.onion import EphemeralOnionService
from txtorcon.onion import AuthenticatedHiddenService

from torconfig import FakeControlProtocol


class OnionServiceTest(unittest.TestCase):

    @defer.inlineCallbacks
    def test_descriptor_all_uploads_fail(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        eph_d = EphemeralOnionService.create(config, ports=["80 127.0.0.1:80"])

        cmd, d = protocol.commands[0]
        self.assertEqual(u"ADD_ONION NEW:BEST Port=80,127.0.0.1:80", cmd)
        d.callback("PrivateKey=fakeprivatekeyblob\nServiceID=onionfakehostname")

        # get the event-listener callback that torconfig code added
        cb = protocol.events['HS_DESC']

        for x in range(6):
            cb('UPLOAD onionfakehostname UNKNOWN hsdir_{}'.format(x))

        for x in range(6):
            cb('FAILED onionfakehostname UNKNOWN hsdir_{}'.format(x))

        # now when we wait for our onion, it should already be failed
        # because all 6 uploads failed.
        with self.assertRaises(RuntimeError) as ctx:
            yield eph_d

        self.assertIn("Failed to upload", str(ctx.exception))
        for x in range(6):
            self.assertIn("hsdir_{}".format(x), str(ctx.exception))


class EphemeralHiddenServiceTest(unittest.TestCase):
    def test_defaults(self):
        eph = torconfig.EphemeralHiddenService("80 localhost:80")
        self.assertEqual(eph._ports, ["80,localhost:80"])

    def test_wrong_blob(self):
        wrong_blobs = ["", " ", "foo", ":", " : ", "foo:", ":foo", 0]
        for b in wrong_blobs:
            try:
                torconfig.EphemeralHiddenService("80 localhost:80", b)
                self.fail("should get exception")
            except ValueError:
                pass

    def test_add(self):
        eph = torconfig.EphemeralHiddenService("80 127.0.0.1:80")
        proto = Mock()
        proto.queue_command = Mock(return_value="PrivateKey=blam\nServiceID=ohai")
        eph.add_to_tor(proto)

        self.assertEqual("blam", eph.private_key)
        self.assertEqual("ohai.onion", eph.hostname)

    def test_add_keyblob(self):
        eph = torconfig.EphemeralHiddenService("80 127.0.0.1:80", "alg:blam")
        proto = Mock()
        proto.queue_command = Mock(return_value="ServiceID=ohai")
        eph.add_to_tor(proto)

        self.assertEqual("alg:blam", eph.private_key)
        self.assertEqual("ohai.onion", eph.hostname)

    def test_descriptor_wait(self):
        eph = torconfig.EphemeralHiddenService("80 127.0.0.1:80")
        proto = Mock()
        proto.queue_command = Mock(return_value=defer.succeed("PrivateKey=blam\nServiceID=ohai\n"))

        eph.add_to_tor(proto)

        # get the event-listener callback that torconfig code added;
        # the last call [-1] was to add_event_listener; we want the
        # [1] arg of that
        cb = proto.method_calls[-1][1][1]

        # Tor doesn't actually provide the .onion, but we can test it anyway
        cb('UPLOADED ohai UNKNOWN somehsdir')
        cb('UPLOADED UNKNOWN UNKNOWN somehsdir')

        self.assertEqual("blam", eph.private_key)
        self.assertEqual("ohai.onion", eph.hostname)

    def test_remove(self):
        eph = torconfig.EphemeralHiddenService("80 127.0.0.1:80")
        eph.hostname = 'foo.onion'
        proto = Mock()
        proto.queue_command = Mock(return_value="OK")

        eph.remove_from_tor(proto)

    @defer.inlineCallbacks
    def test_remove_error(self):
        eph = torconfig.EphemeralHiddenService("80 127.0.0.1:80")
        eph.hostname = 'foo.onion'
        proto = Mock()
        proto.queue_command = Mock(return_value="it's not ok")

        try:
            yield eph.remove_from_tor(proto)
            self.fail("should have gotten exception")
        except RuntimeError:
            pass

    def test_failed_upload(self):
        eph = torconfig.EphemeralHiddenService("80 127.0.0.1:80")
        proto = Mock()
        proto.queue_command = Mock(return_value=defer.succeed("PrivateKey=seekrit\nServiceID=42\n"))

        d = eph.add_to_tor(proto)

        # get the event-listener callback that torconfig code added;
        # the last call [-1] was to add_event_listener; we want the
        # [1] arg of that
        cb = proto.method_calls[-1][1][1]

        # Tor leads with UPLOAD events for each attempt; we queue 2 of
        # these...
        cb('UPLOAD 42 UNKNOWN hsdir0')
        cb('UPLOAD 42 UNKNOWN hsdir1')

        # ...but fail them both
        cb('FAILED 42 UNKNOWN hsdir1 REASON=UPLOAD_REJECTED')
        cb('FAILED 42 UNKNOWN hsdir0 REASON=UPLOAD_REJECTED')

        self.assertEqual("seekrit", eph.private_key)
        self.assertEqual("42.onion", eph.hostname)
        self.assertTrue(d.called)
        d.addErrback(lambda e: self.assertTrue('Failed to upload' in str(e)))

    def test_single_failed_upload(self):
        eph = torconfig.EphemeralHiddenService("80 127.0.0.1:80")
        proto = Mock()
        proto.queue_command = Mock(return_value=defer.succeed("PrivateKey=seekrit\nServiceID=42\n"))

        d = eph.add_to_tor(proto)

        # get the event-listener callback that torconfig code added;
        # the last call [-1] was to add_event_listener; we want the
        # [1] arg of that
        cb = proto.method_calls[-1][1][1]

        # Tor leads with UPLOAD events for each attempt; we queue 2 of
        # these...
        cb('UPLOAD 42 UNKNOWN hsdir0')
        cb('UPLOAD 42 UNKNOWN hsdir1')

        # ...then fail one
        cb('FAILED 42 UNKNOWN hsdir1 REASON=UPLOAD_REJECTED')
        # ...and succeed on the last.
        cb('UPLOADED 42 UNKNOWN hsdir0')

        self.assertEqual("seekrit", eph.private_key)
        self.assertEqual("42.onion", eph.hostname)
        self.assertTrue(d.called)
