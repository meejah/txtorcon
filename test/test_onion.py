from __future__ import print_function

import os
import sys
from mock import Mock
from os.path import join
from unittest import skipIf

from twisted.trial import unittest
from twisted.internet import defer

from txtorcon import TorConfig
from txtorcon import torconfig

from txtorcon.onion import FilesystemOnionService
from txtorcon.onion import FilesystemAuthenticatedOnionService
from txtorcon.onion import EphemeralOnionService
from txtorcon.onion import EphemeralAuthenticatedOnionService
from txtorcon.onion import AuthStealth, AuthBasic, DISCARD
from txtorcon.onion import _validate_ports_low_level

from txtorcon.testutil import FakeControlProtocol


_test_private_key = (
    u'-----BEGIN RSA PRIVATE KEY-----\n'
    u'MIICXAIBAAKBgQC+bxV7+iEjJCmvQW/2SOYFQBsF06VuAdVKr3xTNMHgqI5mks6O\n'
    u'D8cizQ1nr0bL/bqtLPA2whUSvaJmDZjkmpC62v90YU1p99tGOv+ILZTzoIIjcWWn\n'
    u'3muDzA7p+zlN50x55ABuxEwQ3TfRA6nM1JF4HamYuHNae5nzbdwuxXpQ4wIDAQAB\n'
    u'AoGBAJLjbkf11M+dWkXjjLAE5OAR5YYmDYmAAnycRaKMpCtc+JIoFQlBJFI0pm1e\n'
    u'ppY8fVyMuDEUnVqaSYS8Yj2a95zD84hr0SzNFf5wSbffEcLIsmw7I18Mxq/YMrmy\n'
    u'oGwizMnhV/IVPKh40xctPl2cIpg9AdBLYgnc/sO8oBr5k+uRAkEA8B4jeVq4IYv/\n'
    u'b/kPzWiav/9weFMqKZdDh0O7ashbRe4b6CaHI2+XxX4uop9bFCTXsq73yCL7gqpU\n'
    u'AkzCPGWvmwJBAMsHqQQjKn7KlPezZsYL4FY2IkqKuq2x6vFWhMPfXl6y66Ya6/uO\n'
    u'of5kJUlolVcbvAEq4kLAk7nWi9RzWux/DFkCQHk1HX8StkPo4YZqWPm9RfCJRwLW\n'
    u'KEBaZPIQ1LhwbvJ74YZsfGb828YLjgr1GgqvFlrSS62xSviIdmO6z4mhYuUCQAK9\n'
    u'E7aOkuAq819z+Arr1hbTnBrNTD9Tiwu+UwQhWzCD0VHoQw6dmenIiAg5dOo74YlS\n'
    u'fsLPvi5fintPIwbVn+ECQCh6PEvaTP+fsPTyaRPOftCPqgLZbfzGnmt3ZJh1EB60\n'
    u'6X5Sz7FXRbQ8G5kmBy7opEoT4vsLMWGI+uq5WCXiuqY=\n'
    u'-----END RSA PRIVATE KEY-----'
)
_test_onion_id = u'n7vc7sxqwqrm3vwo'  # corresponds to above key
# same as above private key, but without the markers + newlines
# (e.g. for ADD_ONION etc)
_test_private_key_blob = u''.join(_test_private_key.split(u'\n')[1:-1])


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
            f.write(u'{}.onion'.format(_test_onion_id))

        hs_d = FilesystemOnionService.create(
            Mock(),
            config,
            hsdir=hsdir,
            ports=["80 127.0.0.1:4321"],
            version=3,
        )

        # arrange HS_DESC callbacks so we get the hs instance back
        cb = protocol.events['HS_DESC']
        for x in range(6):
            cb('UPLOAD {} UNKNOWN hsdir_{}'.format(_test_onion_id, x))
        for x in range(6):
            cb('UPLOADED {} UNKNOWN hsdir_{}'.format(_test_onion_id, x))

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
            f.write('{}.onion'.format(_test_onion_id))

        hs_d = FilesystemOnionService.create(
            Mock(),
            config,
            hsdir=hsdir,
            ports=["80 127.0.0.1:4321"],
            version=3,
        )

        # arrange HS_DESC callbacks so we get the hs instance back
        cb = protocol.events['HS_DESC']
        cb('UPLOAD {} UNKNOWN hsdir0'.format(_test_onion_id))
        cb('UPLOADED {} UNKNOWN hsdir0'.format(_test_onion_id))

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
            f.write('{}.onion'.format(_test_onion_id))

        hs_d = FilesystemOnionService.create(
            Mock(),
            config,
            hsdir=hsdir0,
            ports=["80 127.0.0.1:4321"],
            version=3,
        )

        # arrange HS_DESC callbacks so we get the hs instance back
        cb = protocol.events['HS_DESC']
        cb('UPLOAD {} UNKNOWN hsdir0'.format(_test_onion_id))
        cb('UPLOADED {} UNKNOWN hsdir0'.format(_test_onion_id))

        hs = yield hs_d

        hs.dir = hsdir1
        self.assertEqual(hs.dir, hsdir1)

    @defer.inlineCallbacks
    def test_dir_ioerror(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        hsdir = self.mktemp()
        os.mkdir(hsdir)
        with open(join(hsdir, "hostname"), "w") as f:
            f.write("{}.onion".format(_test_onion_id))

        hs_d = FilesystemOnionService.create(
            Mock(),
            config,
            hsdir=hsdir,
            ports=["80 127.0.0.1:4321"],
        )

        # arrange HS_DESC callbacks so we get the hs instance back
        cb = protocol.events['HS_DESC']
        cb('UPLOAD {} UNKNOWN hsdir0'.format(_test_onion_id))
        cb('UPLOADED {} UNKNOWN hsdir0'.format(_test_onion_id))

        hs = yield hs_d
        self.assertIs(None, hs.private_key)

    @defer.inlineCallbacks
    def test_dir_ioerror_v3(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        hsdir = self.mktemp()
        os.mkdir(hsdir)
        with open(join(hsdir, "hostname"), "w") as f:
            f.write('{}.onion'.format(_test_onion_id))

        hs_d = FilesystemOnionService.create(
            Mock(),
            config,
            hsdir=hsdir,
            ports=["80 127.0.0.1:4321"],
            version=3,
        )

        # arrange HS_DESC callbacks so we get the hs instance back
        cb = protocol.events['HS_DESC']
        cb('UPLOAD {} UNKNOWN hsdir0'.format(_test_onion_id))
        cb('UPLOADED {} UNKNOWN hsdir0'.format(_test_onion_id))

        hs = yield hs_d
        self.assertIs(None, hs.private_key)

    @defer.inlineCallbacks
    def test_unknown_version(self):
        protocol = FakeControlProtocol([])
        protocol.version = "0.1.1.1"
        config = TorConfig(protocol)
        hsdir = self.mktemp()
        os.mkdir(hsdir)

        hs = yield FilesystemOnionService.create(
            Mock(),
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

        # returns a Deferred we're ignoring
        EphemeralOnionService.create(
            Mock(),
            config,
            ports=["80 127.0.0.1:80"],
            private_key=_test_private_key_blob,
            detach=True,
        )

        cmd, d = protocol.commands[0]
        self.assertEqual(u"ADD_ONION RSA1024:{} Port=80,127.0.0.1:80 Flags=Detach".format(_test_private_key_blob), cmd)
        d.callback("PrivateKey={}\nServiceID={}".format(_test_private_key_blob, _test_onion_id))

    def test_ephemeral_key_whitespace0(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        d = EphemeralOnionService.create(
            Mock(),
            config,
            ports=["80 127.0.0.1:80"],
            private_key=_test_private_key_blob + '\r',
            detach=True,
        )
        return self.assertFailure(d, ValueError)

    def test_ephemeral_key_whitespace1(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        d = EphemeralOnionService.create(
            Mock(),
            config,
            ports=["80 127.0.0.1:80"],
            private_key=_test_private_key_blob + '\n',
            detach=True,
        )
        return self.assertFailure(d, ValueError)

    def test_ephemeral_v3_no_key(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        # returns a Deferred we're ignoring
        EphemeralOnionService.create(
            Mock(),
            config,
            ports=["80 127.0.0.1:80"],
            detach=True,
            version=3,
        )

        cmd, d = protocol.commands[0]
        self.assertEqual(u"ADD_ONION NEW:ED25519-V3 Port=80,127.0.0.1:80 Flags=Detach", cmd)
        d.callback("PrivateKey={}\nServiceID={}".format(_test_private_key_blob, _test_onion_id))

    def test_ephemeral_v3_ip_addr_tuple(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        # returns a Deferred we're ignoring
        EphemeralOnionService.create(
            Mock(),
            config,
            ports=[(80, "192.168.1.2:80")],
            detach=True,
            version=3,
        )

        cmd, d = protocol.commands[0]
        self.assertEqual(u"ADD_ONION NEW:ED25519-V3 Port=80,192.168.1.2:80 Flags=Detach", cmd)
        d.callback("PrivateKey={}\nServiceID={}".format(_test_private_key_blob, _test_onion_id))

    def test_ephemeral_v3_non_anonymous(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        # returns a Deferred we're ignoring
        EphemeralOnionService.create(
            Mock(),
            config,
            ports=[(80, "192.168.1.2:80")],
            version=3,
            detach=True,
            single_hop=True,
        )

        cmd, d = protocol.commands[0]
        self.assertEqual(u"ADD_ONION NEW:ED25519-V3 Port=80,192.168.1.2:80 Flags=Detach,NonAnonymous", cmd)
        d.callback("PrivateKey={}\nServiceID={}".format(_test_private_key_blob, _test_onion_id))

    @defer.inlineCallbacks
    def test_ephemeral_v3_ip_addr_tuple_non_local(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        # returns a Deferred we're ignoring
        with self.assertRaises(ValueError):
            yield EphemeralOnionService.create(
                Mock(),
                config,
                ports=[(80, "hostname:80")],
                detach=True,
                version=3,
            )

    @defer.inlineCallbacks
    def test_ephemeral_v3_wrong_key_type(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        privkey = 'RSA1024:{}'.format('a' * 32)

        with self.assertRaises(ValueError) as ctx:
            yield EphemeralOnionService.create(
                Mock(),
                config,
                ports=["80 127.0.0.1:80"],
                detach=True,
                version=3,
                private_key=privkey,
            )
        self.assertIn(
            "but private key isn't",
            str(ctx.exception),
        )

    @defer.inlineCallbacks
    def test_ephemeral_ports_not_a_list(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        privkey = 'a' * 32

        with self.assertRaises(ValueError) as ctx:
            yield EphemeralOnionService.create(
                Mock(),
                config,
                ports="80 127.0.0.1:80",
                private_key=privkey,
            )
        self.assertIn(
            "'ports' must be a list of strings",
            str(ctx.exception)
        )

    def test_ephemeral_ports_not_strings(self):
        with self.assertRaises(ValueError) as ctx:
            _validate_ports_low_level([(80, "127.0.0.1:80")])
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
                Mock(),
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
                Mock(),
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
                Mock(),
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
                Mock(),
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
                Mock(),
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
            Mock(),
            config,
            ports=["80 127.0.0.1:80"],
            progress=progress,
            private_key=DISCARD,
        )

        cmd, d = protocol.commands[0]
        self.assertEqual(u"ADD_ONION NEW:BEST Port=80,127.0.0.1:80 Flags=DiscardPK", cmd)
        d.callback("PrivateKey={}\nServiceID={}".format(_test_private_key_blob, _test_onion_id))

        # get the event-listener callback that torconfig code added
        cb = protocol.events['HS_DESC']

        for x in range(6):
            cb('UPLOAD {} UNKNOWN hsdir_{}'.format(_test_onion_id, x))

        for x in range(6):
            cb('FAILED {} UNKNOWN hsdir_{}'.format(_test_onion_id, x))

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
            Mock(),
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
            Mock(),
            config,
            ports=["80 127.0.0.1:80"],
        )

        cmd, d = protocol.commands[0]
        self.assertEqual(u"ADD_ONION NEW:BEST Port=80,127.0.0.1:80", cmd)

        d.callback("PrivateKey={}\nServiceID={}".format(_test_private_key_blob, _test_onion_id))
        cb = protocol.events['HS_DESC']

        for x in range(6):
            cb('UPLOAD {} UNKNOWN hsdir_{}'.format(_test_onion_id, x))

        for x in range(6):
            cb('UPLOADED {} UNKNOWN hsdir_{}'.format(_test_onion_id, x))

        hs = yield eph_d
        remove_d = hs.remove()
        cmd, d = protocol.commands[-1]
        self.assertEqual(u"DEL_ONION {}".format(_test_onion_id), cmd)
        d.callback('OK')
        yield remove_d

    @defer.inlineCallbacks
    def test_ephemeral_remove_not_ok(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        eph_d = EphemeralOnionService.create(
            Mock(),
            config,
            ports=["80 127.0.0.1:80"],
        )

        cmd, d = protocol.commands[0]
        self.assertEqual(u"ADD_ONION NEW:BEST Port=80,127.0.0.1:80", cmd)

        d.callback("PrivateKey={}\nServiceID={}".format(_test_private_key_blob, _test_onion_id))
        cb = protocol.events['HS_DESC']

        for x in range(6):
            cb('UPLOAD {} UNKNOWN hsdir_{}'.format(_test_onion_id, x))

        for x in range(6):
            cb('UPLOADED {} UNKNOWN hsdir_{}'.format(_test_onion_id, x))

        hs = yield eph_d
        remove_d = hs.remove()
        cmd, d = protocol.commands[-1]
        self.assertEqual(u"DEL_ONION {}".format(_test_onion_id), cmd)
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
                Mock(),
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
            Mock(),
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
            f.write('{}.onion'.format(_test_onion_id))

        def my_progress(a, b, c):
            pass

        eph_d = FilesystemOnionService.create(
            Mock(),
            config,
            hsdir,
            ports=["80 127.0.0.1:80"],
            progress=my_progress,
            version=3,
        )

        # arrange HS_DESC callbacks so we get the hs instance back
        cb = protocol.events['HS_DESC']
        cb('UPLOAD {} UNKNOWN hsdir0'.format(_test_onion_id))
        cb('UPLOADED {} UNKNOWN hsdir0'.format(_test_onion_id))

        yield eph_d

    @defer.inlineCallbacks
    def test_tor_version_v3_progress_await_all(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)
        hsdir = self.mktemp()
        os.mkdir(hsdir)
        with open(join(hsdir, "hostname"), "w") as f:
            f.write('{}.onion'.format(_test_onion_id))

        class Bad(Exception):
            pass

        def my_progress(a, b, c):
            raise Bad("it's bad")

        eph_d = FilesystemOnionService.create(
            Mock(),
            config,
            hsdir,
            ports=["80 127.0.0.1:80"],
            progress=my_progress,
            version=3,
            await_all_uploads=True,
        )

        # arrange HS_DESC callbacks so we get the hs instance back
        cb = protocol.events['HS_DESC']
        cb('UPLOAD {} UNKNOWN hsdir0'.format(_test_onion_id))
        cb('UPLOADED {} UNKNOWN hsdir0'.format(_test_onion_id))

        yield eph_d
        errs = self.flushLoggedErrors(Bad)
        self.assertEqual(3, len(errs))  # because there's a "100%" one too

    @skipIf('pypy' in sys.version.lower(), "Weird OpenSSL+PyPy problem on Travis")
    @defer.inlineCallbacks
    def test_ephemeral_auth_basic(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        eph_d = EphemeralAuthenticatedOnionService.create(
            Mock(),
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

        d.callback("PrivateKey={}\nServiceID={}\nClientAuth=steve:aseekritofsomekind".format(_test_private_key_blob, _test_onion_id))
        cb = protocol.events['HS_DESC']

        for x in range(6):
            cb('UPLOAD {} UNKNOWN hsdir_{}'.format(_test_onion_id, x))

        for x in range(6):
            cb('UPLOADED {} UNKNOWN hsdir_{}'.format(_test_onion_id, x))

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
            "{}.onion".format(_test_onion_id),
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
            "{}.onion".format(_test_onion_id),
            carol.hostname,
        )

        remove_d = hs.remove()
        cmd, d = protocol.commands[-1]
        self.assertEqual(u"DEL_ONION {}".format(_test_onion_id), cmd)
        d.callback('OK')
        yield remove_d

    @skipIf('pypy' in sys.version.lower(), "Weird OpenSSL+PyPy problem on Travis")
    @defer.inlineCallbacks
    def test_ephemeral_auth_basic_remove_fails(self):
        protocol = FakeControlProtocol([])
        config = TorConfig(protocol)

        eph_d = EphemeralAuthenticatedOnionService.create(
            Mock(),
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

        d.callback(
            "PrivateKey={}\nServiceID={}\nClientAuth=steve:aseekritofsomekind".format(
                _test_private_key_blob,
                _test_onion_id,
            )
        )
        cb = protocol.events['HS_DESC']

        for x in range(6):
            cb('UPLOAD {} UNKNOWN hsdir_{}'.format(_test_onion_id, x))

        for x in range(6):
            cb('UPLOADED {} UNKNOWN hsdir_{}'.format(_test_onion_id, x))

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
            "{}.onion".format(_test_onion_id),
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
            "{}.onion".format(_test_onion_id),
            carol.hostname,
        )

        remove_d = hs.remove()
        cmd, d = protocol.commands[-1]
        self.assertEqual(u"DEL_ONION {}".format(_test_onion_id), cmd)
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
                Mock(),
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
                Mock(),
                config,
                ports="80 127.0.0.1:80",
                auth=AuthBasic(["xavier"]),
            )
        self.assertIn(
            "'ports' must be a list of strings",
            str(ctx.exception),
        )

    def test_ephemeral_ports_bad1(self):
        with self.assertRaises(ValueError) as ctx:
            _validate_ports_low_level([80])
        self.assertIn(
            "'ports' must be a list of strings",
            str(ctx.exception),
        )

    def test_ephemeral_ports_bad2(self):
        with self.assertRaises(ValueError) as ctx:
            _validate_ports_low_level("not even a list")
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


class AuthenticatedFilesystemHiddenServiceTest(unittest.TestCase):

    def setUp(self):
        self.thedir = self.mktemp()
        os.mkdir(self.thedir)
        protocol = FakeControlProtocol([])
        self.config = TorConfig(protocol)
        self.hs = FilesystemAuthenticatedOnionService(
            config=self.config,
            thedir=self.thedir,
            ports=["80 127.0.0.1:1234"],
            auth=AuthBasic(['foo', 'bar'])
        )

    def test_create_progress_old_tor(self):
        hsdir = "/dev/null"
        ports = ["80 127.0.0.1:1234"]

        def progress(pct, tag, msg):
            pass  # print(pct, tag, msg)
        self.config.tor_protocol.version = "0.2.0.0"
        FilesystemAuthenticatedOnionService.create(
            Mock(), self.config, hsdir, ports,
            auth=AuthBasic(['alice']),
            progress=progress,
        )

    def test_unknown_auth_type(self):
        with self.assertRaises(ValueError) as ctx:
            FilesystemAuthenticatedOnionService(
                self.config, self.thedir, ["80 127.0.0.1:1234"],
                auth=object(),
            )
        self.assertIn(
            "must be one of AuthBasic or AuthStealth",
            str(ctx.exception),
        )

    def test_bad_client_name(self):
        with self.assertRaises(ValueError) as ctx:
            FilesystemAuthenticatedOnionService(
                self.config, self.thedir, ["80 127.0.0.1:1234"],
                auth=AuthBasic(["bob can't have spaces"]),
            )
        self.assertIn(
            "can't have spaces",
            str(ctx.exception),
        )

    def test_get_client_missing(self):
        with open(join(self.thedir, "hostname"), "w") as f:
            f.write(
                "foo.onion fooauthtoken # client: foo\n"
                "bar.onion barauthtoken # client: bar\n"
            )
        with self.assertRaises(KeyError) as ctx:
            self.hs.get_client("quux")
        self.assertIn(
            "No such client",
            str(ctx.exception),
        )

    def test_get_client(self):
        with open(join(self.thedir, "hostname"), "w") as f:
            f.write(
                "foo.onion fooauthtoken # client: foo\n"
                "bar.onion barauthtoken # client: bar\n"
            )

        client = self.hs.get_client("foo")
        with self.assertRaises(KeyError):
            client.private_key
        client.group_readable

    def test_get_client_private_key_error(self):
        with open(join(self.thedir, "hostname"), "w") as f:
            f.write(
                "foo.onion fooauthtoken # client: foo\n"
                "bar.onion barauthtoken # client: bar\n"
            )
        with open(join(self.thedir, "client_keys"), "w") as f:
            f.write("foo blargly baz baz\n")

        client = self.hs.get_client("foo")
        with self.assertRaises(RuntimeError) as ctx:
            client.private_key
        self.assertIn(
            "Parse error at",
            str(ctx.exception),
        )

    def test_get_client_expected_not_found(self):
        self.hs = FilesystemAuthenticatedOnionService(
            self.config, self.thedir, ["80 127.0.0.1:1234"],
            auth=AuthBasic(["foo", "bar", "baz"]),
        )
        with open(join(self.thedir, "hostname"), "w") as f:
            f.write(
                "foo.onion fooauthtoken # client: foo\n"
                "bar.onion barauthtoken # client: bar\n"
            )

        with self.assertRaises(RuntimeError) as ctx:
            self.hs.get_client("baz")
        self.assertIn(
            "Didn't find expected client",
            str(ctx.exception),
        )
