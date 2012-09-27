from twisted.internet import defer
from util import NetLocation

import types
import datetime

def hexIdFromHash(thehash):
    """
    From the base-64 encoded hashes Tor uses, this produces the longer
    hex-encoded hashes.
    """
    return "$" + (thehash + "=").decode("base64").encode("hex").upper()


def hashFromHexId(hexid):
    """
    From a hex fingerprint id, convert back to base-64 encoded value.
    """
    if hexid[0] == '$':
        hexid = hexid[1:]
    return hexid.decode("hex").encode("base64")[:-2]


class PortRange(object):
    """
    Represents a range of ports for Router policies.
    """
    def __init__(self, a, b):
        self.min = a
        self.max = b
        
    def __cmp__(self, b):
        if b >= self.min and b <= self.max:
            return 0
        return 1
    
    def __str__(self):
        return "%d-%d" % (self.min, self.max)


def load_routers_from_consensus(file_or_fname):
    """
    FIXME: move to a helpers.py file or something. OR better yet, can
    we just use Stem's instead?

    This loads from a file like cached-consensus (WITHOUT checking
    signatures, etcetera; you have Tor for that) and returns a list of
    Router instances.
    """

    try:
        f = open(file_or_fname, 'r')
    except TypeError:
        f = file_or_fname

    routers = []
    current_router = None
    
    for line in f.readlines():
        args = line.split()
        if args[0] == 'r':
            if current_router:
                routers.append(current_router)
            current_router = Router()
            current_router.update(args[1],         # nickname
                                  args[2],         # idhash
                                  args[3],         # orhash
                                  datetime.datetime.strptime(args[4]+args[5], '%Y-%m-%f%H:%M:%S'),
                                  args[6],         # ip address
                                  args[7],         # ORPort
                                  args[8])         # DirPort
        elif args[0] == 's':
            current_router.set_flags(args[1:])
        elif args[0] == 'w':
            current_router.set_bandwidth(int(args[1].split('=')[1]))
        elif args[0] == 'p':
            current_router.set_policy(args[1:])
        ## FIXME not parsing version lines
    routers.append(current_router)
    return routers        

class Router(object):
    """
    Represents a Tor Router, including location.

    The controller you pass in is really only used to do get_info
    calls for ip-to-country/IP in case the
    :class:`txtorcon.util.NetLocation` stuff fails to find a country.

    After an .update() call, the id_hex attribute contains a
    hex-encoded long hash (suitable, for example, to use in a
    ``GETINFO ns/id/*`` call).

    After setting the policy property you may call accepts_port() to
    find out if the router will accept a given port. This works with
    the reject or accept based policies.
    """

    def __init__(self, country_finder=lambda x: defer.succeed('??')):
        """
        :param country_finder:
            a callable that takes an IP address and returns a Deferred
            that callbacks with None or a country-code.
        """
       
        self.country_finder = country_finder
        self._flags = []
        self.bandwidth = 0
        self.name_is_unique = False
        self.accepted_ports = None
        self.rejected_ports = None
        self.id_hex = None
        self.location = NetLocation('0.0.0.0')
        self.from_consensus = False

    unique_name = property(lambda x: x.name_is_unique and x.name or x.id_hex)
    "has the hex id if this router's name is not unique, or its name otherwise"

    def update(self, name, idhash, orhash, modified, ip, orport, dirport):
        self.name = name
        self.id_hash = idhash
        self.or_hash = orhash
        self.modified = modified
        self.ip = ip
        self.or_port = orport
        self.dir_port = dirport
        self.location = NetLocation(self.ip)
        if self.location.countrycode is None and self.ip != 'unknown':
            ## see if Tor is magic and knows more...
            self.country_finder(self.ip).addCallback(self._set_country)

        self.id_hex = hexIdFromHash(self.id_hash)

    @property
    def flags(self):
        """
        A list of all the flags for this Router, each one an
        all-lower-case string.
        """
        return self._flags

    @flags.setter
    def flags(self, flags):
        """
        It might be nice to make flags not a list of strings. This is
        made harder by the control-spec: `...controllers MUST tolerate
        unrecognized flags and lines...`

        There is some current work in Twisted for open-ended constants
        (enums) support however, it seems.
        """
        if isinstance(flags, types.StringType):
            flags = flags.split()
        self._flags = map(lambda x: x.lower(), flags)
        self.name_is_unique = 'named' in self._flags

    @property
    def bandwidth(self):
        """The reported bandwidth of this Router."""
        return self._bandwidth
    
    @bandwidth.setter
    def bandwidth(self, bw):
        self._bandwidth = int(bw)

    @property
    def policy(self):
        """
        Port policies for this Router.
        :return: a string describing the policy
        """
        if self.accepted_ports:
            ports = 'accept '
            target = self.accepted_ports
        else:
            ports = 'reject '
            target = self.rejected_ports

        if target is None:
            return ''

        last = None
        for x in target:
            ports = ports + str(x) + ','
        return ports[:-1]

    @policy.setter
    def policy(self, args):
        """
        setter for the policy descriptor
        """

        word = args[0]
        if word == 'reject':
            self.accepted_ports = None
            self.rejected_ports = []
            target = self.rejected_ports

        elif word == 'accept':
            self.accepted_ports = []
            self.rejected_ports = None
            target = self.accepted_ports

        else:
            raise RuntimeError("Don't understand policy word \"%s\"" % word)

        for port in args[1].split(','):
            if '-' in port:
                (a, b) = port.split('-')
                target.append(PortRange(int(a), int(b)))
            else:
                target.append(int(port))

    def accepts_port(self, port):
        """
        Query whether this Router will accept the given port.
        """

        if self.rejected_ports is None and self.accepted_ports is None:
            raise RuntimeError("policy hasn't been set yet")

        if self.rejected_ports:
            for x in self.rejected_ports:
                if port == x:
                    return False
            return True

        for x in self.accepted_ports:
            if port == x:
                return True
        return False

    def _set_country(self, c):
        """
        Callback from the country_finder callable (e.g. usually this
        uses Tor's GETINFO ip-to-country); see how torstate.py
        instantiates Router objects.
        """

        self.location.countrycode = c
        if '=' in c:
            self.location.countrycode = c[:-3].split('=')[1].strip().upper()

    def __repr__(self):
        n = self.id_hex
        if self.name_is_unique:
            n = self.name
        return "<Router %s %s %s>" % (n, self.location.countrycode,
                                      self.policy)
