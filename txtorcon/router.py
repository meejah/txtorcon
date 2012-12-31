from util import NetLocation
import types


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

    def __init__(self, controller):
        self.controller = controller
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
            self.controller.get_info_raw('ip-to-country/' + self.ip).addCallback(self._set_country)

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
            return 'accept ' + ','.join(map(str, self.accepted_ports))
        elif self.rejected_ports:
            return 'reject ' + ','.join(map(str, self.rejected_ports))
        else:
            return ''

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
        callback if we used Tor's GETINFO ip-to-country
        """

        self.location.countrycode = c[:-3].split('=')[1].strip().upper()

    def __repr__(self):
        n = self.id_hex
        if self.name_is_unique:
            n = self.name
        return "<Router %s %s %s>" % (n, self.location.countrycode,
                                      self.policy)
