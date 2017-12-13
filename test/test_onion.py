from __future__ import print_function

import os
from mock import Mock
from os.path import join

from twisted.trial import unittest
from twisted.internet import defer

from txtorcon import TorConfig
from txtorcon import torconfig

from txtorcon.onion import FilesystemOnionService
from txtorcon.onion import EphemeralOnionService
from txtorcon.onion import EphemeralAuthenticatedOnionService
from txtorcon.onion import AuthStealth, AuthBasic, DISCARD

from txtorcon.testutil import FakeControlProtocol


class OnionServiceTest(unittest.TestCase):

    @defer.inlineCallbacks
    def test_prop224_private_key(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        hsdir = self.mktemp()
        os.mkdir(hsdir)
        with open(join(hsdir, 'hs_ed25519_secret_key'), 'wb') as f:
            f.write(b'\x01\x02\x03\x04')
        with open(join(hsdir, 'hostname'), 'w') as f:
            f.write(u'onionfakehostname.onion')

        hs_d = FilesystemOnionService.create(
            config,
            hsdir=hsdir,
            ports=["80 127.0.0.1:4321"],
            version=3,
        )

        # arrange HS_DESC callbacks so we get the hs instance back
        cb = protocol.events['HS_DESC']
        for x in range(6):
            cb('UPLOAD onionfakehostname UNKNOWN hsdir_{}'.format(x))
        for x in range(6):
            cb('UPLOADED onionfakehostname UNKNOWN hsdir_{}'.format(x))

        hs = yield hs_d

        self.assertEqual(b'\x01\x02\x03\x04', hs.private_key)

    @defer.inlineCallbacks
    def test_set_ports(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        hsdir = self.mktemp()
        os.mkdir(hsdir)
        with open(join(hsdir, 'hs_ed25519_secret_key'), 'wb') as f:
            f.write(b'\x01\x02\x03\x04')
        with open(join(hsdir, 'hostname'), 'w') as f:
            f.write('onionfakehostname.onion')

        hs_d = FilesystemOnionService.create(
            config,
            hsdir=hsdir,
            ports=["80 127.0.0.1:4321"],
            version=3,
        )

        # arrange HS_DESC callbacks so we get the hs instance back
        cb = protocol.events['HS_DESC']
        cb('UPLOAD onionfakehostname UNKNOWN hsdir0')
        cb('UPLOADED onionfakehostname UNKNOWN hsdir0')

        hs = yield hs_d
        hs.ports = ["443 127.0.0.1:443"]
        self.assertEqual(1, len(hs.ports))

    @defer.inlineCallbacks
    def test_set_dir(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        hsdir0 = self.mktemp()
        os.mkdir(hsdir0)
        hsdir1 = self.mktemp()
        os.mkdir(hsdir1)

        with open(join(hsdir0, "hostname"), "w") as f:
            f.write('onionfakehostname.onion')

        hs_d = FilesystemOnionService.create(
            config,
            hsdir=hsdir0,
            ports=["80 127.0.0.1:4321"],
            version=3,
        )

        # arrange HS_DESC callbacks so we get the hs instance back
        cb = protocol.events['HS_DESC']
        cb('UPLOAD onionfakehostname UNKNOWN hsdir0')
        cb('UPLOADED onionfakehostname UNKNOWN hsdir0')

        hs = yield hs_d

        hs.dir = hsdir1
        self.assertEqual(hs.dir, hsdir1)

    @defer.inlineCallbacks
    def test_unknown_version(self):
        protocol = FakeControlProtocol([])
        protocol.version = "0.1.1.1"
        config = TorConfig(protocol)
        hsdir = self.mktemp()
        os.mkdir(hsdir)

        hs = yield FilesystemOnionService.create(
            config,
            hsdir=hsdir,
            ports=["80 127.0.0.1:4321"],
            version=99,
        )

        with self.assertRaises(RuntimeError) as ctx:
            hs.private_key
        self.assertIn("Don't know how to load", str(ctx.exception))

    def test_ephemeral_given_key(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        privkey = 'a' * 32

        # returns a Deferred we're ignoring
        EphemeralOnionService.create(
            config,
            ports=["80 127.0.0.1:80"],
            private_key=privkey,
            detach=True,
        )

        cmd, d = protocol.commands[0]
        self.assertEqual(u"ADD_ONION RSA1024:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa Port=80,127.0.0.1:80 Flags=Detach", cmd)
        d.callback("PrivateKey=fakeprivatekeyblob\nServiceID=onionfakehostname")

    @defer.inlineCallbacks
    def test_ephemeral_ports_not_a_list(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        privkey = 'a' * 32

        with self.assertRaises(ValueError) as ctx:
            yield EphemeralOnionService.create(
                config,
                ports="80 127.0.0.1:80",
                private_key=privkey,
            )
        self.assertIn(
            "'ports' must be a list of strings",
            str(ctx.exception)
        )

    @defer.inlineCallbacks
    def test_ephemeral_ports_not_strings(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        privkey = 'a' * 32

        with self.assertRaises(ValueError) as ctx:
            yield EphemeralOnionService.create(
                config,
                ports=[(80, "127.0.0.1:80")],
                private_key=privkey,
            )
        self.assertIn(
            "'ports' must be a list of strings",
            str(ctx.exception)
        )

    @defer.inlineCallbacks
    def test_ephemeral_ports_no_spaces(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        privkey = 'a' * 32

        with self.assertRaises(ValueError) as ctx:
            yield EphemeralOnionService.create(
                config,
                ports=["80:127.0.0.1:80"],
                private_key=privkey,
            )
        self.assertIn(
            "exactly one space",
            str(ctx.exception)
        )

    @defer.inlineCallbacks
    def test_ephemeral_ports_no_colon(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        privkey = 'a' * 32

        with self.assertRaises(ValueError) as ctx:
            yield EphemeralOnionService.create(
                config,
                ports=["80 127.0.0.1;80"],
                private_key=privkey,
            )
        self.assertIn(
            "local address should be 'IP:port'",
            str(ctx.exception)
        )

    @defer.inlineCallbacks
    def test_ephemeral_ports_non_local(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        privkey = 'a' * 32

        with self.assertRaises(ValueError) as ctx:
            yield EphemeralOnionService.create(
                config,
                ports=["80 8.8.8.8:80"],
                private_key=privkey,
            )
        self.assertIn(
            "should be a local address",
            str(ctx.exception)
        )

    @defer.inlineCallbacks
    def test_ephemeral_ports_not_an_int(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        privkey = 'a' * 32

        with self.assertRaises(ValueError) as ctx:
            yield EphemeralOnionService.create(
                config,
                ports=["web 127.0.0.1:80"],
                private_key=privkey,
            )
        self.assertIn(
            "external port isn't an int",
            str(ctx.exception)
        )

    @defer.inlineCallbacks
    def test_filesystem_wrong_ports(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        with self.assertRaises(ValueError) as ctx:
            yield FilesystemOnionService.create(
                config,
                "/dev/null",
                ports="80 127.0.0.1:80",
            )
        self.assertIn(
            "'ports' must be a list of strings",
            str(ctx.exception)
        )

    @defer.inlineCallbacks
    def test_descriptor_all_uploads_fail(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        progress_messages = []

        def progress(*args):
            progress_messages.append(args)
        eph_d = EphemeralOnionService.create(
            config,
            ports=["80 127.0.0.1:80"],
            progress=progress,
            private_key=DISCARD,
        )

        cmd, d = protocol.commands[0]
        self.assertEqual(u"ADD_ONION NEW:BEST Port=80,127.0.0.1:80 Flags=DiscardPK", cmd)
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

    def test_ephemeral_bad_return_value(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        progress_messages = []

        def progress(*args):
            progress_messages.append(args)
        eph_d = EphemeralOnionService.create(
            config,
            ports=["80 127.0.0.1:80"],
            progress=progress,
            private_key=DISCARD,
        )

        cmd, d = protocol.commands[0]
        self.assertEqual(u"ADD_ONION NEW:BEST Port=80,127.0.0.1:80 Flags=DiscardPK", cmd)

        d.callback("BadKey=nothing")

        def check(f):
            self.assertIn("Expected ADD_ONION to return ServiceID", str(f.value))
            return None
        eph_d.addCallbacks(self.fail, check)
        return eph_d

    @defer.inlineCallbacks
    def test_ephemeral_remove(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        eph_d = EphemeralOnionService.create(
            config,
            ports=["80 127.0.0.1:80"],
        )

        cmd, d = protocol.commands[0]
        self.assertEqual(u"ADD_ONION NEW:BEST Port=80,127.0.0.1:80", cmd)

        d.callback("PrivateKey=fakeprivatekeyblob\nServiceID=onionfakehostname")
        cb = protocol.events['HS_DESC']

        for x in range(6):
            cb('UPLOAD onionfakehostname UNKNOWN hsdir_{}'.format(x))

        for x in range(6):
            cb('UPLOADED onionfakehostname UNKNOWN hsdir_{}'.format(x))

        hs = yield eph_d
        remove_d = hs.remove()
        cmd, d = protocol.commands[-1]
        self.assertEqual(u"DEL_ONION onionfakehostname", cmd)
        d.callback('OK')
        yield remove_d

    @defer.inlineCallbacks
    def test_ephemeral_remove_not_ok(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        eph_d = EphemeralOnionService.create(
            config,
            ports=["80 127.0.0.1:80"],
        )

        cmd, d = protocol.commands[0]
        self.assertEqual(u"ADD_ONION NEW:BEST Port=80,127.0.0.1:80", cmd)

        d.callback("PrivateKey=fakeprivatekeyblob\nServiceID=onionfakehostname")
        cb = protocol.events['HS_DESC']

        for x in range(6):
            cb('UPLOAD onionfakehostname UNKNOWN hsdir_{}'.format(x))

        for x in range(6):
            cb('UPLOADED onionfakehostname UNKNOWN hsdir_{}'.format(x))

        hs = yield eph_d
        remove_d = hs.remove()
        cmd, d = protocol.commands[-1]
        self.assertEqual(u"DEL_ONION onionfakehostname", cmd)
        d.callback('bad stuff')
        with self.assertRaises(RuntimeError):
            yield remove_d

    def test_ephemeral_ver_option(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        hs = EphemeralOnionService(
            config,
            ports=["80 127.0.0.1:80"],
            ver=2,
        )
        self.assertEqual(2, hs.version)

    def test_ephemeral_extra_kwargs(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        with self.assertRaises(ValueError) as ctx:
            EphemeralOnionService(
                config,
                ports=["80 127.0.0.1:80"],
                ver=2,
                something_funny="foo",
            )
        self.assertIn(
            "Unknown kwarg",
            str(ctx.exception),
        )

    @defer.inlineCallbacks
    def test_ephemeral_auth_stealth(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        with self.assertRaises(ValueError) as ctx:
            yield EphemeralAuthenticatedOnionService.create(
                config,
                ports=["80 127.0.0.1:80"],
                auth=AuthStealth(["steve", "carol"]),
            )
        self.assertIn(
            "Tor does not yet support",
            str(ctx.exception),
        )

    @defer.inlineCallbacks
    def test_old_tor_version(self):
        protocol = FakeControlProtocol([])
        protocol.version = "0.1.2.3"
        config = TorConfig(protocol)
        hsdir = self.mktemp()

        def my_progress(a, b, c):
            pass

        eph_d = FilesystemOnionService.create(
            config,
            hsdir,
            ports=["80 127.0.0.1:80"],
            progress=my_progress,
        )
        yield eph_d

    @defer.inlineCallbacks
    def test_tor_version_v3_progress(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        hsdir = self.mktemp()
        os.mkdir(hsdir)
        with open(join(hsdir, "hostname"), "w") as f:
            f.write("onionfakehostname.onion")

        def my_progress(a, b, c):
            pass

        eph_d = FilesystemOnionService.create(
            config,
            hsdir,
            ports=["80 127.0.0.1:80"],
            progress=my_progress,
            version=3,
        )

        # arrange HS_DESC callbacks so we get the hs instance back
        cb = protocol.events['HS_DESC']
        cb('UPLOAD onionfakehostname UNKNOWN hsdir0')
        cb('UPLOADED onionfakehostname UNKNOWN hsdir0')

        yield eph_d

    @defer.inlineCallbacks
    def test_ephemeral_auth_basic(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        eph_d = EphemeralAuthenticatedOnionService.create(
            config,
            ports=["80 127.0.0.1:80"],
            auth=AuthBasic([
                "steve",
                ("carol", "c4r0ls33kr1t"),
            ]),
        )
        cmd, d = protocol.commands[0]
        self.assertTrue(
            cmd.startswith(
                u"ADD_ONION NEW:BEST Port=80,127.0.0.1:80 Flags=BasicAuth "
            )
        )
        self.assertIn(u"ClientAuth=steve", cmd)
        self.assertIn(u"ClientAuth=carol:c4r0ls33kr1t", cmd)

        d.callback("PrivateKey=fakeprivatekeyblob\nServiceID=onionfakehostname\nClientAuth=steve:aseekritofsomekind")
        cb = protocol.events['HS_DESC']

        for x in range(6):
            cb('UPLOAD onionfakehostname UNKNOWN hsdir_{}'.format(x))

        for x in range(6):
            cb('UPLOADED onionfakehostname UNKNOWN hsdir_{}'.format(x))

        hs = yield eph_d

        self.assertEqual(
            set(["steve", "carol"]),
            set(hs.client_names()),
        )
        steve = hs.get_client("steve")
        self.assertEqual(
            "aseekritofsomekind",
            steve.auth_token,
        )
        self.assertEqual(
            "onionfakehostname.onion",
            steve.hostname,
        )
        self.assertEqual(
            set(["80 127.0.0.1:80"]),
            steve.ports,
        )
        self.assertTrue(steve.parent is hs)
        self.assertEqual("steve", steve.name)
        self.assertEqual(2, steve.version)

        carol = hs.get_client("carol")
        self.assertEqual(
            "c4r0ls33kr1t",
            carol.auth_token,
        )
        self.assertEqual(
            "onionfakehostname.onion",
            carol.hostname,
        )

        remove_d = hs.remove()
        cmd, d = protocol.commands[-1]
        self.assertEqual(u"DEL_ONION onionfakehostname", cmd)
        d.callback('OK')
        yield remove_d


    @defer.inlineCallbacks
    def test_ephemeral_auth_basic_remove_fails(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        eph_d = EphemeralAuthenticatedOnionService.create(
            config,
            ports=["80 127.0.0.1:80"],
            auth=AuthBasic([
                "steve",
                ("carol", "c4r0ls33kr1t"),
            ]),
        )
        cmd, d = protocol.commands[0]
        self.assertTrue(
            cmd.startswith(
                u"ADD_ONION NEW:BEST Port=80,127.0.0.1:80 Flags=BasicAuth "
            )
        )
        self.assertIn(u"ClientAuth=steve", cmd)
        self.assertIn(u"ClientAuth=carol:c4r0ls33kr1t", cmd)

        d.callback("PrivateKey=fakeprivatekeyblob\nServiceID=onionfakehostname\nClientAuth=steve:aseekritofsomekind")
        cb = protocol.events['HS_DESC']

        for x in range(6):
            cb('UPLOAD onionfakehostname UNKNOWN hsdir_{}'.format(x))

        for x in range(6):
            cb('UPLOADED onionfakehostname UNKNOWN hsdir_{}'.format(x))

        hs = yield eph_d

        self.assertEqual(
            set(["steve", "carol"]),
            set(hs.client_names()),
        )
        steve = hs.get_client("steve")
        self.assertEqual(
            "aseekritofsomekind",
            steve.auth_token,
        )
        self.assertEqual(
            "onionfakehostname.onion",
            steve.hostname,
        )
        self.assertEqual(
            set(["80 127.0.0.1:80"]),
            steve.ports,
        )
        self.assertTrue(steve.parent is hs)
        self.assertEqual("steve", steve.name)
        self.assertEqual(2, steve.version)

        carol = hs.get_client("carol")
        self.assertEqual(
            "c4r0ls33kr1t",
            carol.auth_token,
        )
        self.assertEqual(
            "onionfakehostname.onion",
            carol.hostname,
        )

        remove_d = hs.remove()
        cmd, d = protocol.commands[-1]
        self.assertEqual(u"DEL_ONION onionfakehostname", cmd)
        d.callback('not okay')
        with self.assertRaises(RuntimeError):
            yield remove_d

    def test_ephemeral_auth_basic_bad_name(self):
        with self.assertRaises(ValueError) as ctx:
            AuthBasic(["bad name"])
        self.assertIn(
            "Client names can't have spaces",
            str(ctx.exception),
        )

    @defer.inlineCallbacks
    def test_ephemeral_auth_unknown(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        with self.assertRaises(ValueError) as ctx:
            yield EphemeralAuthenticatedOnionService.create(
                config,
                ports=["80 127.0.0.1:80"],
                auth=["carol", "steve"],
            )
        self.assertIn(
            "'auth' should be an AuthBasic or AuthStealth instance",
            str(ctx.exception),
        )

    @defer.inlineCallbacks
    def test_ephemeral_ports_bad0(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        with self.assertRaises(ValueError) as ctx:
            yield EphemeralAuthenticatedOnionService.create(
                config,
                ports="80 127.0.0.1:80",
                auth=AuthBasic(["xavier"]),
            )
        self.assertIn(
            "'ports' must be a list of strings",
            str(ctx.exception),
        )

    @defer.inlineCallbacks
    def test_ephemeral_ports_bad1(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        with self.assertRaises(ValueError) as ctx:
            yield EphemeralAuthenticatedOnionService.create(
                config,
                ports=[80],
                auth=AuthBasic(["xavier"]),
            )
        self.assertIn(
            "'ports' must be a list of strings",
            str(ctx.exception),
        )


class EphemeralHiddenServiceTest(unittest.TestCase):
    def test_defaults(self):
        eph = torconfig.EphemeralHiddenService(["80 localhost:80"])
        self.assertEqual(eph._ports, ["80,localhost:80"])

    def test_wrong_blob(self):
        wrong_blobs = ["", " ", "foo", ":", " : ", "foo:", ":foo", 0]
        for b in wrong_blobs:
            try:
                torconfig.EphemeralHiddenService(["80 localhost:80"], b)
                self.fail("should get exception")
            except ValueError:
                pass

    def test_add(self):
        eph = torconfig.EphemeralHiddenService(["80 127.0.0.1:80"])
        proto = Mock()
        proto.queue_command = Mock(return_value="PrivateKey=blam\nServiceID=ohai")
        eph.add_to_tor(proto)

        self.assertEqual("blam", eph.private_key)
        self.assertEqual("ohai.onion", eph.hostname)

    def test_add_keyblob(self):
        eph = torconfig.EphemeralHiddenService(["80 127.0.0.1:80"], "alg:blam")
        proto = Mock()
        proto.queue_command = Mock(return_value="ServiceID=ohai")
        eph.add_to_tor(proto)

        self.assertEqual("alg:blam", eph.private_key)
        self.assertEqual("ohai.onion", eph.hostname)

    def test_descriptor_wait(self):
        eph = torconfig.EphemeralHiddenService(["80 127.0.0.1:80"])
        proto = Mock()
        proto.queue_command = Mock(return_value=defer.succeed("PrivateKey=blam\nServiceID=ohai\n"))

        eph.add_to_tor(proto)

        # get the event-listener callback that torconfig code added;
        # the first call [0] was to add_event_listener; we want the
        # [1] arg of that
        cb = proto.method_calls[0][1][1]

        # Tor doesn't actually provide the .onion, but we can test it anyway
        cb('UPLOADED ohai UNKNOWN somehsdir')
        cb('UPLOADED UNKNOWN UNKNOWN somehsdir')

        self.assertEqual("blam", eph.private_key)
        self.assertEqual("ohai.onion", eph.hostname)

    def test_remove(self):
        eph = torconfig.EphemeralHiddenService(["80 127.0.0.1:80"])
        eph.hostname = 'foo.onion'
        proto = Mock()
        proto.queue_command = Mock(return_value="OK")

        eph.remove_from_tor(proto)

    @defer.inlineCallbacks
    def test_remove_error(self):
        eph = torconfig.EphemeralHiddenService(["80 127.0.0.1:80"])
        eph.hostname = 'foo.onion'
        proto = Mock()
        proto.queue_command = Mock(return_value="it's not ok")

        try:
            yield eph.remove_from_tor(proto)
            self.fail("should have gotten exception")
        except RuntimeError:
            pass

    def test_failed_upload(self):
        eph = torconfig.EphemeralHiddenService(["80 127.0.0.1:80"])
        proto = Mock()
        proto.queue_command = Mock(return_value=defer.succeed("PrivateKey=seekrit\nServiceID=42\n"))

        d = eph.add_to_tor(proto)

        # get the event-listener callback that torconfig code added;
        # the first call [0] was to add_event_listener; we want the
        # [1] arg of that
        cb = proto.method_calls[0][1][1]

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
        eph = torconfig.EphemeralHiddenService(["80 127.0.0.1:80"])
        proto = Mock()
        proto.queue_command = Mock(return_value=defer.succeed("PrivateKey=seekrit\nServiceID=42\n"))

        d = eph.add_to_tor(proto)

        # get the event-listener callback that torconfig code added;
        # the first call [0] was to add_event_listener; we want the
        # [1] arg of that
        cb = proto.method_calls[0][1][1]

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
