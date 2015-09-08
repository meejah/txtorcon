# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function
from __future__ import with_statement

import glob
import os
import hmac
import hashlib
import shutil
import socket
import subprocess
import struct

from twisted.internet import defer
from twisted.internet.interfaces import IProtocolFactory

from twisted.internet.endpoints import serverFromString

from zope.interface import implementer

try:
    import GeoIP as _GeoIP
    GeoIP = _GeoIP
except ImportError:
    GeoIP = None

city = None
country = None
asn = None

# XXX probably better to depend on and use "six" for py2/3 stuff?
try:
    unicode
except NameError:
    py3k = True
    basestring = str
else:
    py3k = False
    basestring = basestring


def create_geoip(fname):
    # It's more "pythonic" to just wait for the exception,
    # but GeoIP prints out "Can't open..." messages for you,
    # which isn't desired here
    if not os.path.isfile(fname):
        raise IOError("Can't find %s" % fname)

    if GeoIP is None:
        return None

    # just letting any errors make it out
    return GeoIP.open(fname, GeoIP.GEOIP_STANDARD)


def maybe_create_db(path):
    try:
        return create_geoip(path)
    except IOError:
        return None

city, asn, country = list(map(maybe_create_db,
                         ("/usr/share/GeoIP/GeoLiteCity.dat",
                          "/usr/share/GeoIP/GeoIPASNum.dat",
                          "/usr/share/GeoIP/GeoIP.dat")))

try:
    import ipaddr as _ipaddr
    ipaddr = _ipaddr
except ImportError:
    ipaddr = None


def is_executable(path):
    """Checks if the given path points to an existing, executable file"""
    return os.path.isfile(path) and os.access(path, os.X_OK)


def find_tor_binary(globs=('/usr/sbin/', '/usr/bin/',
                           '/Applications/TorBrowser_*.app/Contents/MacOS/'),
                    system_tor=True):
    """
    Tries to find the tor executable using the shell first or in in the
    paths whose glob-patterns is in the given 'globs'-tuple.

    :param globs:
        A tuple of shell-style globs of directories to use to find tor
        (TODO consider making that globs to actual tor binary?)

    :param system_tor:
        This controls whether bash is used to seach for 'tor' or
        not. If False, we skip that check and use only the 'globs'
        tuple.
    """

    # Try to find the tor executable using the shell
    if system_tor:
        try:
            proc = subprocess.Popen(
                ('which tor'),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=True
            )
        except OSError:
            pass
        else:
            stdout, _ = proc.communicate()
            if proc.poll() == 0 and stdout != '':
                return stdout.strip()

    # the shell may not provide type and tor is usually not on PATH when using
    # the browser-bundle. Look in specific places
    for pattern in globs:
        for path in glob.glob(pattern):
            torbin = os.path.join(path, 'tor')
            if is_executable(torbin):
                return torbin
    return None


def maybe_ip_addr(addr):
    """
    Tries to return an IPAddress, otherwise returns a string.

    TODO consider explicitly checking for .exit or .onion at the end?
    """

    if ipaddr is not None:
        try:
            return ipaddr.IPAddress(addr)
        except ValueError:
            pass
    return str(addr)


def find_keywords(args, key_filter=lambda x: not x.startswith("$")):
    """
    This splits up strings like name=value, foo=bar into a dict. Does NOT deal
    with quotes in value (e.g. key="value with space" will not work

    By default, note that it takes OUT any key which starts with $ (i.e. a
    single dollar sign) since for many use-cases the way Tor encodes nodes
    with "$hash=name" looks like a keyword argument (but it isn't). If you
    don't want this, override the "key_filter" argument to this method.

    :return:
        a dict of key->value (both strings) of all name=value type
        keywords found in args.
    """
    filtered = [x for x in args if '=' in x and key_filter(x.split('=')[0])]
    return dict(x.split('=', 1) for x in filtered)


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


def ip_from_int(ip):
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


def hmac_sha256(key, msg):
    """
    Adapted from rransom's tor-utils git repository. Returns the
    digest (binary) of an HMAC with SHA256 over msg with key.
    """

    return hmac.new(key, msg, hashlib.sha256).digest()


CRYPTOVARIABLE_EQUALITY_COMPARISON_NONCE = os.urandom(32)


def compare_via_hash(x, y):
    """
    Taken from rransom's tor-utils git repository, to compare two
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

        if self.ip is None or self.ip == 'unknown':
            return

        if city:
            try:
                r = city.record_by_addr(self.ip)
            except:
                r = None
            if r is not None:
                self.countrycode = r['country_code']
                self.latlng = (r['latitude'], r['longitude'])
                try:
                    self.city = (r['city'], r['region_code'])
                except KeyError:
                    self.city = (r['city'], r['region_name'])

        elif country:
            self.countrycode = country.country_code_by_addr(ipaddr)

        else:
            self.countrycode = ''

        if asn:
            try:
                self.asn = asn.org_by_addr(self.ip)
            except:
                self.asn = None


@implementer(IProtocolFactory)
class NoOpProtocolFactory:
    """
    This is an IProtocolFactory that does nothing. Used for testing,
    and for :method:`available_tcp_port`
    """
    def noop(self, *args, **kw):
        pass
    buildProtocol = noop
    doStart = noop
    doStop = noop


@defer.inlineCallbacks
def available_tcp_port(reactor):
    """
    Returns a Deferred firing an available TCP port on localhost.
    It does so by listening on port 0; then stopListening and fires the
    assigned port number.
    """

    endpoint = serverFromString(reactor, 'tcp:0:interface=127.0.0.1')
    port = yield endpoint.listen(NoOpProtocolFactory())
    address = port.getHost()
    yield port.stopListening()
    defer.returnValue(address.port)
