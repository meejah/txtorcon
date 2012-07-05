
##
## wrapper for GeoIP since the API for city vs. country is different.
##

import os
import hmac
import hashlib
import shutil
import socket
import subprocess

try:
    import GeoIP

    def create_geoip(fname):
        try:
            ## It's more "pythonic" to just wait for the exception,
            ## but GeoIP prints out "Can't open..." messages for you,
            ## which isn't desired here
            if not os.path.isfile(fname):
                raise IOError("Can't find %s" % fname)
            return GeoIP.open(fname, GeoIP.GEOIP_STANDARD)

        except GeoIP.error:
            raise IOError("Can't load %s" % fname)

except ImportError:
    import pygeoip
    create_geoip = pygeoip.GeoIP

city = None
country = None
asn = None

try:
    city = create_geoip("/usr/share/GeoIP/GeoLiteCity.dat")
except IOError:
    city = None

try:
    asn = create_geoip("/usr/share/GeoIP/GeoIPASNum.dat")
except IOError:
    asn = None

try:
    country = create_geoip("/usr/share/GeoIP/IP.dat")
except IOError:
    country = None


def find_keywords(args):
    """
    This splits up strings like name=value, foo=bar into a dict. Does NOT deal
    with quotes in value (e.g. key="value with space" will not work

    :return:
        a dict of key->value (both strings) of all name=value type
        keywords found in args.
    """
    return dict(x.split('=', 1) for x in args if '=' in x)


def delete_file_or_tree(*args):
    """
    For every path in args, try to delete it as a file or a directory
    tree. Ignores deletion errors.
    """

    for f in args:
        try:
            os.unlink(f)
        except OSError:
            shutil.rmtree(f, ignore_errors=True)


def ip_from_int(self, ip):
        """ Convert long int back to dotted quad string """
        return socket.inet_ntoa(struct.pack('>I', ip))


def process_from_address(addr, port, torstate=None):
    """
    Determines the PID from the address/port provided by using lsof
    and returns it as an int (or None if it couldn't be
    determined). In the special case the addr is '(Tor_internal)' then
    the PID of the Tor process (as gotten from the torstate object) is
    returned (or 0 if unavailable, e.g. a Tor which doesn't implement
    'GETINFO process/pid'). In this case if no TorState instance is
    given, None is returned.
    """

    if addr is None:
        return None

    if "(tor_internal)" == str(addr).lower():
        if torstate is None:
            return None
        return int(torstate.tor_pid)

    proc = subprocess.Popen(['lsof', '-i', '4tcp@%s:%s' % (addr, port)],
                            stdout=subprocess.PIPE)
    (stdout, stderr) = proc.communicate()
    lines = stdout.split('\n')
    if len(lines) > 1:
        return int(lines[1].split()[1])

    return None


def hmac_sha256(key, msg):
    """
    Adapted from rransom's tor-utils git repository. Returns the
    digest (binary) of an HMAC with SHA256 over msg with key.
    """

    return hmac.new(key, msg, hashlib.sha256).digest()


CRYPTOVARIABLE_EQUALITY_COMPARISON_NONCE = os.urandom(32)


def compare_via_hash(x, y):
    """
    Taken from rrandom's tor-utils git repository, to compare two
    hashes in something resembling constant time (or at least, not
    leaking timing info?)
    """
    return (hmac_sha256(CRYPTOVARIABLE_EQUALITY_COMPARISON_NONCE, x) ==
            hmac_sha256(CRYPTOVARIABLE_EQUALITY_COMPARISON_NONCE, y))


class NetLocation:
    """
    Represents the location of an IP address, either city or country
    level resolution depending on what GeoIP database was loaded. If
    the ASN database is available you get that also.
    """

    def __init__(self, ipaddr):
        "ipaddr should be a dotted-quad"
        self.ip = ipaddr
        self.latlng = (None, None)
        self.countrycode = None
        self.city = None
        self.asn = None

        if city:
            r = city.record_by_addr(self.ip)
            if r is not None:
                self.countrycode = r['country_code']
                self.latlng = (r['latitude'], r['longitude'])
                self.city = (r['city'], r['region'])

        elif country:
            self.countrycode = country.country_code_by_addr(ipaddr)

        else:
            self.countrycode = ''

        if asn:
            self.asn = asn.org_by_addr(self.ip)
