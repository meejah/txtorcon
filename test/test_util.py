from mock import patch
from twisted.trial import unittest
from twisted.internet import defer
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet.interfaces import IProtocolFactory
from zope.interface import implements

from txtorcon.util import process_from_address
from txtorcon.util import delete_file_or_tree
from txtorcon.util import find_keywords
from txtorcon.util import ip_from_int
from txtorcon.util import find_tor_binary
from txtorcon.util import maybe_ip_addr

import os
import tempfile


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


class TestIPFromInt(unittest.TestCase):

    def test_cast(self):
        self.assertEqual(ip_from_int(0x7f000001), '127.0.0.1')


class TestGeoIpDatabaseLoading(unittest.TestCase):

    def test_bad_geoip_path(self):
        "fail gracefully if a db is missing"
        from txtorcon import util
        self.assertRaises(IOError, util.create_geoip, '_missing_path_')

    def test_missing_geoip_module(self):
        "return none if geoip module is missing"
        from txtorcon import util
        _GeoIP = util.GeoIP
        util.GeoIP = None
        (fd, f) = tempfile.mkstemp()
        ret_val = util.create_geoip(f)
        delete_file_or_tree(f)
        util.GeoIP = _GeoIP
        self.assertEquals(ret_val, None)

    def test_return_geoip_object(self):
        from txtorcon import util
        (fd, f) = tempfile.mkstemp()
        ret_val = util.create_geoip(f)
        delete_file_or_tree(f)
        self.assertEquals(type(ret_val).__name__, 'GeoIP')


class TestFindKeywords(unittest.TestCase):

    def test_filter(self):
        "make sure we filter out keys that look like router IDs"
        self.assertEqual(
            find_keywords("foo=bar $1234567890=routername baz=quux".split()),
            {'foo': 'bar', 'baz': 'quux'}
        )


class FakeGeoIP(object):
    def __init__(self, version=2):
        self.version = version

    def record_by_addr(self, ip):
        r = dict(country_code='XX',
                 latitude=50.0,
                 longitude=0.0,
                 city='City')
        if self.version == 2:
            r['region_code'] = 'Region'
        else:
            r['region_name'] = 'Region'
        return r


class TestNetLocation(unittest.TestCase):

    def test_valid_lookup_v2(self):
        from txtorcon import util
        orig = util.city
        try:
            util.city = FakeGeoIP(version=2)
            nl = util.NetLocation('127.0.0.1')
            self.assertTrue(nl.city)
            self.assertEquals(nl.city[0], 'City')
            self.assertEquals(nl.city[1], 'Region')
        finally:
            util.ity = orig

    def test_valid_lookup_v3(self):
        from txtorcon import util
        orig = util.city
        try:
            util.city = FakeGeoIP(version=3)
            nl = util.NetLocation('127.0.0.1')
            self.assertTrue(nl.city)
            self.assertEquals(nl.city[0], 'City')
            self.assertEquals(nl.city[1], 'Region')
        finally:
            util.ity = orig

    def test_city_fails(self):
        "make sure we don't fail if the city lookup excepts"
        from txtorcon import util
        orig = util.city
        try:
            class Thrower(object):
                def record_by_addr(*args, **kw):
                    raise RuntimeError("testing failure")
            util.city = Thrower()
            nl = util.NetLocation('127.0.0.1')
            self.assertEqual(None, nl.city)

        finally:
            util.city = orig

    def test_no_city_db(self):
        "ensure we lookup from country if we have no city"
        from txtorcon import util
        origcity = util.city
        origcountry = util.country
        try:
            util.city = None
            obj = object()

            class CountryCoder(object):
                def country_code_by_addr(self, ipaddr):
                    return obj
            util.country = CountryCoder()
            nl = util.NetLocation('127.0.0.1')
            self.assertEqual(obj, nl.countrycode)

        finally:
            util.city = origcity
            util.country = origcountry

    def test_no_city_or_country_db(self):
        "ensure we lookup from asn if we have no city or country"
        from txtorcon import util
        origcity = util.city
        origcountry = util.country
        origasn = util.asn
        try:
            util.city = None
            util.country = None

            class Thrower:
                def org_by_addr(*args, **kw):
                    raise RuntimeError("testing failure")
            util.asn = Thrower()
            nl = util.NetLocation('127.0.0.1')
            self.assertEqual('', nl.countrycode)

        finally:
            util.city = origcity
            util.country = origcountry
            util.asn = origasn


class TestProcessFromUtil(unittest.TestCase):

    def setUp(self):
        self.fakestate = FakeState()

    def test_none(self):
        "ensure we do something useful on a None address"
        self.assertEqual(process_from_address(None, 80, self.fakestate), None)

    def test_internal(self):
        "look up the (Tor_internal) PID"
        pfa = process_from_address('(Tor_internal)', 80, self.fakestate)
        # depends on whether you have psutil installed or not, and on
        # whether your system always has a PID 0 process...
        self.assertEqual(pfa, self.fakestate.tor_pid)

    def test_internal_no_state(self):
        "look up the (Tor_internal) PID"
        pfa = process_from_address('(Tor_internal)', 80)
        # depends on whether you have psutil installed or not, and on
        # whether your system always has a PID 0 process...
        self.assertEqual(pfa, None)

    @defer.inlineCallbacks
    def test_real_addr(self):
        # FIXME should choose a port which definitely isn't used.

        # it's apparently frowned upon to use the "real" reactor in
        # tests, but I was using "nc" before, and I think this is
        # preferable.
        from twisted.internet import reactor
        ep = TCP4ServerEndpoint(reactor, 9887)
        listener = yield ep.listen(FakeProtocolFactory())

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
        self.assertTrue(os.path.exists(os.path.join(d, 'foo')))

        delete_file_or_tree(d)

        self.assertTrue(not os.path.exists(d))
        self.assertTrue(not os.path.exists(os.path.join(d, 'foo')))


class TestFindTor(unittest.TestCase):

    def test_simple_find_tor(self):
        # just test that this doesn't raise an exception
        find_tor_binary()

    def test_find_tor_globs(self):
        "test searching by globs"
        find_tor_binary(system_tor=False)

    def test_find_tor_unfound(self):
        "test searching by globs"
        self.assertEqual(None, find_tor_binary(system_tor=False, globs=()))

    @patch('txtorcon.util.subprocess.Popen')
    def test_find_ioerror(self, popen):
        "test searching with which, but it fails"
        popen.side_effect = OSError
        self.assertEqual(None, find_tor_binary(system_tor=True, globs=()))


class TestIpAddr(unittest.TestCase):

    @patch('txtorcon.util.ipaddr')
    def test_create_ipaddr(self, ipaddr):
        ip = maybe_ip_addr('1.2.3.4')

    @patch('txtorcon.util.ipaddr')
    def test_create_ipaddr(self, ipaddr):
        def foo(blam):
            raise ValueError('testing')
        ipaddr.IPAddress.side_effect = foo
        ip = maybe_ip_addr('1.2.3.4')
