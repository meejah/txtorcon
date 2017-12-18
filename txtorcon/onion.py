import os
import re
import functools

from zope.interface import Interface, Attribute, implementer

from twisted.internet import defer
from twisted.python import log

from txtorcon.util import find_keywords, version_at_least

# XXX
# think: port vs ports: and how do we represent that? i.e. if we
# decide "port" then we have to allow for multiple HiddenSerivce
# instances to have the same private key/hostname but different ports.

# XXX: what about 'detached' versus not onions...

# XXX: okay, so is this now just too many options in one factory
# function?

# XXX: so, should create_onion() "just" be a dispatcher to "more
# specific" factory-functions, like "create_ephemeral_onion"
# "create_detached_onion" "create_permanent_onion??" etc...?
# --> yes.
# --> also: direct people to Tor() thing


## TODO

# - naming:
#   FilesystemOnionService, OnionService vs. FilesystemHiddenService,
#   EphemeralHiddenService, etc. (can the latter just be aliases for
#   the former??)
#


class HiddenServiceClientAuth(object):
    """
    Encapsulates a single client-authorization, as parsed from a
    HiddenServiceDir's "client_keys" file if you have stealth or basic
    authentication turned on.

    :param name: the name you gave it in the HiddenServiceAuthorizeClient line
    :param cookie: random password
    :param key: RSA private key, or None if this was basic auth
    """

    def __init__(self, name, cookie, key=None):
        self.name = name
        self.cookie = cookie
        self.key = parse_rsa_blob(key) if key else None


class IOnionService(Interface):
    """
    Encapsulates a single, ephemeral onion service.

    If this instance happens to be a filesystem-based service (instead
    of ephemeral), it shall implement IFilesystemOnionService as well
    (which is a subclass of this).

    If this object happens to represent an authenticated service, it
    shall implement IAuthenticatedOnionClients ONLY (not this
    interface too; IAuthenticatedOnionClients returns *lists* of
    IOnionClient instances which are a subclass of
    IOnionService; see :class:`txtorcon.IAuthenticatedOnionClients`).

    For non-authenticated services, there will be one of these per
    directory (i.e. HiddenServiceDir) if using non-ephemeral services,
    or one per ADD_ONION for ephemeral hidden services.

    For authenticated services, there is an instance implementing this
    interface for each "client" of the authenticated service. In the
    "basic" case, the .onion URI happens to be the same for each one
    (with a different authethentication token) whereas for a "stealth"
    sevice the .onion URI is different.
    """
    hostname = Attribute("hostname, including .onion")  # XXX *with* .onion? or not?
    private_key = Attribute("Private key blob (bytes)")
    ports = Attribute("list of str; the ports lines like 'public_port host:local_port'")


class IFilesystemOnionService(IOnionService):
    # XXX do we want to expose the directory in the API? probably...
    hidden_service_directory = Attribute('The directory where private data is kept')
    group_readable = Attribute("set HiddenServiceGroupReadable if true")


class IAuthenticatedOnionClients(Interface):
    """
    This encapsulates both 'stealth' and 'basic' authenticated Onion
    (nee Hidden) services, whether ephemeral or not. Note that Tor
    doesn't yet support ephemeral authenticated services.
    """

    def client_names(self):
        """
        :return: list of str instances, one for each client
        """

    def get_client(self, name):
        """
        :return: object implementing IOnionClient for the named client
        """

    def add_client(self, name):
        """
        probably returns a Deferred? god fucking knows
        """

    def del_client(self, name):
        """
        moar deferreds
        """


class IOnionClient(IOnionService):
    """
    A single client from a 'parent' IAuthenticatedOnionClients. We do
    this because hidden services can have different URLs and/or
    auth_tokens on a per-client basis. So, the only way to access
    *anything* from an authenticated onion service is to list the
    cleints -- which gives you one IAuthenticatedOnionClient per
    client.
    """
    auth_token = Attribute('Some secret bytes')
    name = Attribute('str')  # XXX required? probably.
    parent = Attribute('the IAuthenticatedOnionClients instance who owns me')
    # from the IOnionService base interface, inherits:
    #    hostname
    #    private_key
    #    ports


@implementer(IOnionService)
@implementer(IFilesystemOnionService)
class FilesystemOnionService(object):
    """
    """

    @staticmethod
    @defer.inlineCallbacks
    def create(config, hsdir, ports, version=2, group_readable=False, auth=None, progress=None):
        fhs = FilesystemOnionService(config, hsdir, ports, ver=version, group_readable=group_readable, auth=auth)
        config.HiddenServices.append(fhs)
        # we .save() down below, after setting HS_DESC listener

        # XXX I *hate* this version checking crap. Can we discover a
        # different way if this Tor supports proper HS_DESC stuff? I
        # think part of the problem here is that "some" Tors have
        # HS_DESC event, but it's not .. sufficient?
        uploaded = [None]
        if not version_at_least(config.tor_protocol.version, 0, 2, 7, 2):
            if progress:
                progress(
                    102, "wait_desctiptor",
                    "Adding an onion service to Tor requires at least version"
                )
                progress(
                    103, "wait_desctiptor",
                    "0.2.7.2 so that HS_DESC events work properly and we can"
                )
                progress(
                    104, "wait_desctiptor",
                    "detect our desctiptor being uploaded."
                )
                progress(
                    105, "wait_desctiptor",
                    "Your version is '{}'".format(config.tor_protocol.version),
                )
                progress(
                    106, "wait_desctiptor",
                    "So, we'll just declare it done right now..."
                )
                uploaded[0] = defer.succeed(None)
        else:
            # XXX actually, there's some versions of Tor when v3
            # filesystem services could be added but they didn't send
            # HS_DESC updates -- did any of these actually get
            # released?!
            uploaded[0] = _await_descriptor_upload(config.tor_protocol, fhs, progress)

        yield config.save()
        yield uploaded[0]
        defer.returnValue(fhs)

    def __init__(self, config, thedir, ports,
                 auth=None, ver=2, group_readable=0):
        if not isinstance(ports, list):
            raise ValueError("'ports' must be a list of strings")
        self._config = config
        self._dir = os.path.realpath(thedir)
        from .torconfig import _ListWrapper
        self._ports = _ListWrapper(
            ports,
            functools.partial(config.mark_unsaved, 'HiddenServices'),
        )
        self._auth = auth
        self._version = ver
        self._group_readable = group_readable
        self._hostname = None
        self._private_key = None

    @property
    def hostname(self):
        if self._hostname is None:
            try:
                with open(os.path.join(self._dir, 'hostname'), 'r') as f:
                    self._hostname = f.read().strip()
            except IOError:
                # not clear under what circumstances this happens
                # (i.e. we can create a new onion, but somehow not
                # read the hostname file) but ... safety?
                self._hostname = None
        return self._hostname

    @property
    def private_key(self):
        # XXX there's also a file called 'hs_ed25519_public_key' but I
        # think we can just ignore that? .. or do we need a v3-only
        # accessor for .public_key() as well?
        if self._private_key is None:
            if self.version == 2:
                try:
                    with open(os.path.join(self._dir, 'private_key'), 'r') as f:
                        self._private_key = f.read().strip()
                except IOError:
                    # not clear under what circumstances this happens
                    # (i.e. we can create a new onion, but somehow not
                    # read the private_key file) but ... safety?
                    self._private_key = None
            elif self.version == 3:
                # XXX see tor bug #20699 -- would be Really Nice to
                # not have to deal with binary data here (well, more
                # for ADD_ONION, but still)
                try:
                    with open(os.path.join(self._dir, 'hs_ed25519_secret_key'), 'rb') as f:
                        self._private_key = f.read().strip()
                except IOError:
                    # not clear under what circumstances this happens
                    # (i.e. we can create a new onion, but somehow not
                    # read the private key file) but ... safety?
                    self._private_key = None
            else:
                raise RuntimeError(
                    "Don't know how to load private_key for version={} "
                    "Onion service".format(self.version)
                )
        return self._private_key

    @property
    def ports(self):
        return self._ports

    @ports.setter
    def ports(self, ports):
        # XXX FIXME need to update Tor's notion of config and/or
        # reject this request after we *have* updated Tor..."or
        # something"
        from .torconfig import _ListWrapper
        self._ports = _ListWrapper(
            ports,
            functools.partial(self._config.mark_unsaved, 'HiddenServices'),
        )
        self._config.mark_unsaved('HiddenServices')

    @property
    def dir(self):  # XXX propbably should be 'directory'?
        return self._dir

    @dir.setter
    def dir(self, d):
        self._dir = d  # XXX FIXME see above
        self._config.mark_unsaved('HiddenServices')

    @property
    def group_readable(self):
        return self._group_readable

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, v):
        self._version = v
        self._config.mark_unsaved('HiddenServices')

    @property
    def authorize_client(self):
        if self._auth is None:
            return []
        return [
            "{} {}".format(
                self._auth.auth_type,
                ','.join(self._auth.client_names()),
            )
        ]

    # etcetc, basically the old "HiddenService" object

    def config_attributes(self):
        rtn = [('HiddenServiceDir', str(self._dir))]
        if self._config._supports['HiddenServiceDirGroupReadable'] \
           and self.group_readable:
            rtn.append(('HiddenServiceDirGroupReadable', str(1)))
        for x in self.ports:
            rtn.append(('HiddenServicePort', str(x)))
        if self.version:
            rtn.append(('HiddenServiceVersion', str(self.version)))
        for authline in self.authorize_client:
            rtn.append(('HiddenServiceAuthorizeClient', str(authline)))
            # rtn.append(('HiddenServiceAuthorizeClient', str(self.authorize_client)))
        return rtn


@defer.inlineCallbacks
def _await_descriptor_upload(tor_protocol, onion, progress):
    """
    Internal helper.

    :param tor_protocol: ITorControlProtocol instance

    :param onion: IOnionService instance

    :param progress: a progess callback, or None

    :returns: a Deferred that fires once we've detected at least one
        descriptor upload for the service (as detected by listening for
        HS_DESC events)
    """
    pct = 101.0
    attempted_uploads = set()
    confirmed_uploads = set()
    failed_uploads = set()
    uploaded = defer.Deferred()

    def hs_desc(evt):
        """
        From control-spec:
        "650" SP "HS_DESC" SP Action SP HSAddress SP AuthType SP HsDir
        [SP DescriptorID] [SP "REASON=" Reason] [SP "REPLICA=" Replica]
        """
        global pct
        args = evt.split()
        subtype = args[0]
        if subtype == 'UPLOAD':
            if onion.hostname and args[1] == onion.hostname[:-6]:
                attempted_uploads.add(args[3])
                if progress:
                    progress(
                        101 + (len(attempted_uploads) + len(failed_uploads)) / 2.0,
                        "wait_descriptor",
                        "Upload to {} started".format(args[3])
                    )

        elif subtype == 'UPLOADED':
            # we only need ONE successful upload to happen for the
            # HS to be reachable.
            # unused? addr = args[1]

            # XXX FIXME I think tor is sending the onion-address
            # properly with these now, so we can use those
            # (i.e. instead of matching to "attempted_uploads")
            if args[3] in attempted_uploads:
                if progress:
                    progress(
                        101 + (len(attempted_uploads) + len(failed_uploads)) / 2.0,
                        "wait_descriptor",
                        "Successful upload to {}".format(args[3])
                    )
                confirmed_uploads.add(args[3])
                log.msg("Uploaded '{}' to '{}'".format(onion.hostname, args[3]))
                if not uploaded.called:
                    uploaded.callback(onion)

        elif subtype == 'FAILED':
            if onion.hostname and args[1] == onion.hostname[:-6]:
                failed_uploads.add(args[3])
                if progress:
                    progress(
                        101 + (len(attempted_uploads) + len(failed_uploads)) / 2.0,
                        "wait_descriptor",
                        "Failed upload to {}".format(args[3])
                    )
                if failed_uploads == attempted_uploads:
                    msg = "Failed to upload '{}' to: {}".format(
                        onion.hostname,
                        ', '.join(failed_uploads),
                    )
                    uploaded.errback(RuntimeError(msg))

    # the first 'yield' should be the add_event_listener so that a
    # caller can do "d = _await_descriptor_upload()", then add the
    # service.
    yield tor_protocol.add_event_listener('HS_DESC', hs_desc)
    yield uploaded
    yield tor_protocol.remove_event_listener('HS_DESC', hs_desc)


@defer.inlineCallbacks
def _add_ephemeral_service(config, onion, progress, version, auth=None):
    """
    Internal Helper.

    This uses ADD_ONION to add the given service to Tor. The Deferred
    this returns will callback when the ADD_ONION call has succeed,
    *and* when at least one descriptor has been uploaded to a Hidden
    Service Directory.

    :param config: a TorConfig instance

    :param onion: an EphemeralOnionService instance

    :param progress: a callable taking 3 arguments (percent, tag,
        description) that is called some number of times to tell you of
        progress.

    :param version: 2 or 3, which kind of service to create

    :param auth: if not None, create an authenticated service ("basic"
        is the only kind supported currently so a AuthBasic instance
        should be passed)
    """
    if onion not in config.EphemeralOnionServices:
        config.EphemeralOnionServices.append(onion)

    # we have to keep this as a Deferred for now so that HS_DESC
    # listener gets added before we issue ADD_ONION
    assert version in (2, 3)
    uploaded_d = _await_descriptor_upload(config.tor_protocol, onion, progress)

    # we allow a key to be passed that *doestn'* start with
    # "RSA1024:" because having to escape the ":" for endpoint
    # string syntax (which uses ":" as delimeters) is annoying
    # XXX rethink ^^? what do we do when the type is upgraded?
    # maybe just a magic-character that's different from ":", or
    # force people to escape them?
    if onion.private_key:
        if onion.private_key is not DISCARD and ':' not in onion.private_key:
            if version == 2:
                if not onion.private_key.startswith("RSA1024:"):
                    onion._private_key = "RSA1024:" + onion.private_key
            elif version == 3:
                if not onion.private_key.startswith("ED25519-V3:"):
                    onion._private_key = "ED25519-V3:" + onion.private_key

    # okay, we're set up to listen, and now we issue the ADD_ONION
    # command. this will set ._hostname and ._private_key properly
    keystring = 'NEW:BEST'
    if onion.private_key not in (None, DISCARD):
        keystring = onion.private_key
    elif version == 3:
        keystring = 'NEW:ED25519-V3'
    if version == 3:
        if 'V3' not in keystring:
            raise ValueError(
                "version=3 but private key isn't 'ED25519-V3'"
            )

    cmd = 'ADD_ONION {}'.format(keystring)
    for port in onion._ports:
        cmd += ' Port={},{}'.format(*port.split(' ', 1))
    flags = []
    if onion._detach:
        flags.append('Detach')
    # XXX from below, make "private_key=THROW_AWAY" the way to do this?
    if onion.private_key is DISCARD:
        flags.append('DiscardPK')
    if auth is not None:
        assert isinstance(auth, AuthBasic)  # don't support AuthStealth yet
        if isinstance(auth, AuthBasic):
            flags.append('BasicAuth')
    if flags:
        cmd += ' Flags={}'.format(','.join(flags))

    if auth is not None:
        for client_name in auth.client_names():
            keyblob = auth.keyblob_for(client_name)
            if keyblob is None:
                cmd += ' ClientAuth={}'.format(client_name)
            else:
                cmd += ' ClientAuth={}:{}'.format(client_name, keyblob)
                onion._add_client(client_name, keyblob)

    raw_res = yield config.tor_protocol.queue_command(cmd)
    res = find_keywords(raw_res.split('\n'))
    try:
        onion._hostname = res['ServiceID'] + '.onion'
        if onion.private_key is DISCARD:
            onion._private_key = None
        else:
            # if we specified a private key, it's not echoed back
            if not onion.private_key:
                onion._private_key = res['PrivateKey']
    except KeyError:
        raise RuntimeError(
            "Expected ADD_ONION to return ServiceID= and PrivateKey= args."
            "Got: {}".format(res)
        )

    if auth is not None:
        for line in raw_res.split('\n'):
            if line.startswith("ClientAuth="):
                name, blob = line[11:].split(':', 1)
                onion._add_client(name, blob)

    log.msg("{}: waiting for descriptor uploads.".format(onion.hostname))
    yield uploaded_d


class _AuthCommon(object):

    def __init__(self, clients):
        self._clients = dict()
        for client in clients:
            if isinstance(client, tuple):
                client_name, keyblob = client
                self._clients[client_name] = keyblob
            else:
                self._clients[client] = None
        if any(' ' in client for client in self._clients.keys()):
            raise ValueError("Client names can't have spaces")

    def client_names(self):
        return self._clients.keys()

    def keyblob_for(self, client_name):
        return self._clients[client_name]


class AuthNone(object):
    pass


class AuthBasic(_AuthCommon):
    auth_type = 'basic'


class AuthStealth(_AuthCommon):
    auth_type = 'stealth'


DISCARD = object()


@implementer(IAuthenticatedOnionClients)
class EphemeralAuthenticatedOnionService(object):

    # XXX as per discussion below w/ kurt looks like I decided on
    # something like "auth=NoAuth()", "auth=AuthBasic(["alice",
    # "bob"])" or "auth=StealthAuth(["alice", "bob"])" or similar.
    @classmethod
    @defer.inlineCallbacks
    def create(cls, config, ports,
               detach=False,
               private_key=None,  # or DISCARD or a key
               version=None,
               progress=None,
               auth=None):  # AuthBasic, or AuthStealth instance

        """
        """
        if not isinstance(auth, (AuthBasic, AuthStealth)):
            raise ValueError(
                "'auth' should be an AuthBasic or AuthStealth instance"
            )

        if isinstance(auth, AuthStealth):
            raise ValueError(
                "Tor does not yet support ephemeral stealth-auth"
            )

        version = 2 if version is None else version
        assert version in (2, 3)

        onion = EphemeralAuthenticatedOnionService(
            config, ports,
            private_key=private_key,
            detach=detach,
            version=version,
        )
        yield _add_ephemeral_service(config, onion, progress, version, auth)

        defer.returnValue(onion)

    def __init__(self, config, ports, hostname=None, private_key=None, auth=[], version=2,
                 detach=False):
        """
        Users should create instances of this class by using the async
        method :meth:`txtorcon.EphemeralAuthenticatedOnionService.create`
        """

        _validate_ports(ports)

        self._config = config
        self._ports = ports
        self._hostname = hostname
        self._private_key = private_key
        self._version = version
        self._detach = detach
        self._clients = dict()

    def client_names(self):
        return self._clients.keys()

    def get_client(self, name):
        return self._clients[name]

    def _add_client(self, name, auth_token):
        self._clients[name] = EphemeralAuthenticatedOnionServiceClient(
            parent=self,
            name=name,
            token=auth_token,
        )

    @property
    def hostname(self):
        return self._hostname

    @property
    def ports(self):
        return set(self._ports)

    @property
    def version(self):
        return self._version

    @property
    def private_key(self):
        return self._private_key

    @defer.inlineCallbacks
    def remove(self):
        """
        Issues a DEL_ONION call to our tor, removing this service.
        """
        cmd = 'DEL_ONION {}'.format(self._hostname[:-len('.onion')])
        res = yield self._config.tor_protocol.queue_command(cmd)
        if res.strip() != "OK":
            raise RuntimeError("Failed to remove service")


@implementer(IOnionService)
class EphemeralOnionService(object):
    @classmethod
    @defer.inlineCallbacks
    def create(cls, config, ports,
               detach=False,
               private_key=None,  # or DISCARD
               version=None,
               progress=None):
        """
        returns a new EphemeralOnionService after adding it to the
        provided config and ensuring at least one of its descriptors
        is uploaded.

        :param config: a :class:`txtorcon.TorConfig` instance

        :param ports: a list of ports to make available; any of these
            can be 2-tuples of (remote, local) if you want to expose a
            particular port locally (otherwise, an available one is
            chosen)

        See also :meth:`txtorcon.Tor.create_onion_service` (which
        ultimately calls this).
        """
        version = 2 if version is None else version
        assert version in (2, 3)

        onion = EphemeralOnionService(
            config, ports,
            hostname=None,
            private_key=private_key,
            detach=detach,
            version=version,
        )

        yield _add_ephemeral_service(config, onion, progress, version)

        defer.returnValue(onion)

    def __init__(self, config, ports, hostname=None, private_key=None, version=2,
                 detach=False, **kwarg):
        """
        Users should create instances of this class by using the async
        method :meth:`txtorcon.EphemeralOnionService.create`
        """

        # prior to 17.0.0, this took an argument called "ver" instead
        # of "version". So, we will silently upgrade that.
        if "ver" in kwarg:
            version = int(kwarg.pop("ver"))
        # any other kwargs are illegal
        if len(kwarg):
            raise ValueError(
                "Unknown kwargs: {}".format(", ".join(kwarg.keys()))
            )

        _validate_ports(ports)

        self._config = config
        self._ports = ports
        self._hostname = hostname
        self._private_key = private_key
        self._version = version
        self._detach = detach

    # not putting an "add_to_tor" method here; that class is now
    # deprecated and you add one of these by using .create()

    @defer.inlineCallbacks
    def remove(self):
        """
        Issues a DEL_ONION call to our tor, removing this service.
        """
        cmd = 'DEL_ONION {}'.format(self._hostname[:-len('.onion')])
        res = yield self._config.tor_protocol.queue_command(cmd)
        if res.strip() != "OK":
            raise RuntimeError("Failed to remove service")

    @property
    def ports(self):
        return set(self._ports)

    @property
    def version(self):
        return self._version

    @property
    def hostname(self):
        return self._hostname

    @property
    def private_key(self):
        return self._private_key


@implementer(IOnionClient)
class EphemeralAuthenticatedOnionServiceClient(object):
    """
    A single client of an EphemeralAuthenticatedOnionService

    These are only created by and returned from the .clients property
    of an AuthenticatedOnionService instance.

    # needs 'auth_token', 'name', 'parent' for IOnionClient
    """

    def __init__(self, parent, name, token):
        self._parent = parent
        self._name = name
        self._auth_token = token

    @property
    def name(self):
        return self._name

    @property
    def ports(self):
        return set(self._parent.ports)

    @property
    def hostname(self):
        return self._parent.hostname

    @property
    def auth_token(self):
        return self._auth_token

    @property
    def parent(self):
        return self._parent

    @property
    def version(self):
        return self._parent.version


@implementer(IOnionClient)
class AuthenticatedHiddenServiceClient(object):
    """
    A single client of an AuthenticatedHiddenService

    These are only created by and returned from the .clients property
    of an AuthenticatedHiddenService instance.
    """

    def __init__(self, parent, name, hostname, ports, token):
        self._parent = parent
        self._name = name
        self.hostname = hostname
        self.auth_token = token
        self.ephemeral = False
        self._ports = ports
        # XXX private_key?
        # XXX group_readable

    @property
    def name(self):
        return self._name

    @property
    def parent(self):
        return self._parent

    @property
    def ports(self):
        return self._ports

    @property
    def private_key(self):
        # yes, needs to come from "clients" file i think?
        return self._parent._private_key(self._name).key

    @property
    def group_readable(self):
        return self._parent.group_readable

    @property
    def authorize_client(self):
        return '{} {}'.format(self._name, self.auth_token)

    @property
    def hidden_service_directory(self):
        return self._parent.hidden_service_directory

    @property
    def version(self):
        return self._parent.version


@implementer(IAuthenticatedOnionClients)
class AuthenticatedHiddenService(object):
    """
    Corresponds to::

      HiddenServiceDir /home/mike/src/tor/hidserv-stealth
      HiddenServiceDirGroupReadable 1
      HiddenServicePort 80 127.0.0.1:99
      HiddenServiceAuthorizeClient stealth quux,flummox,zinga

    or::

      HiddenServiceDir /home/mike/src/tor/hidserv-basic
      HiddenServiceDirGroupReadable 1
      HiddenServicePort 80 127.0.0.1:99
      HiddenServiceAuthorizeClient basic foo,bar,baz
    """
    # XXX should take "auth={AuthBasic, AuthStealth}" like the other thing...
    def __init__(self, config, thedir, ports, auth_type='basic', clients=None, ver=2, group_readable=0):
        # XXX do we need version here? probably...
        self._config = config
        self._dir = thedir
        self._ports = ports
        self._auth_type = auth_type
        if auth_type not in ['basic', 'stealth']:
            raise ValueError("Unknown auth_type '{}'".format(auth_type))
        # dict: name -> IAuthenticatedOnionClient
        self._clients = None
        self._expected_clients = clients
        if clients and any(' ' in client for client in clients):
            raise ValueError("Client names can't have spaces")
        self._version = ver
        self._group_readable = group_readable
        self._client_keys = None

    @property
    def hidden_service_directory(self):
        return self._dir

    @property
    def group_readable(self):
        return self._group_readable

    @property
    def ports(self):
        return self._ports

    @property
    def version(self):
        return self._version

    # basically everything in HiddenService, except the only API we
    # provide is "clients" because there's a separate .onion hostname
    # and authentication token per client.

    def client_names(self):
        """
        IAuthenticatedOnionClients API
        """
        if self._clients is None:
            self._parse_hostname()
        return self._clients.keys()

    def get_client(self, name):
        """
        IAuthenticatedOnionClients API
        """
        if self._clients is None:
            self._parse_hostname()
        try:
            return self._clients[name]
        except KeyError:
            raise KeyError("No such client '{}'".format(name))

    def add_client(self, name, hostname, ports, token):
        if self._clients is None:
            self._parse_hostname()
        client = AuthenticatedHiddenServiceClient(
            parent=self,
            name=name,
            hostname=hostname,
            ports=ports, token=token,
        )
        self._clients[client.name] = client
        self._config.HiddenServices.append(client)

    def _private_key(self, name):
        if self._client_keys is None:
            self._parse_client_keys()
        return self._client_keys[name]

    def _parse_client_keys(self):
        try:
            with open(os.path.join(self._dir, 'client_keys'), 'r') as f:
                keys = parse_client_keys(f)
        except IOError:
            keys = []
        self._client_keys = {}
        for auth in keys:
            self._client_keys[auth.name] = auth

    def _parse_hostname(self):
        clients = {}
        with open(os.path.join(self._dir, 'hostname')) as f:
            for idx, line in enumerate(f.readlines()):
                # lines are like: hex.onion hex # client: name
                m = re.match("(.*) (.*) # client: (.*)", line)
                hostname, cookie, name = m.groups()
                # -> for auth'd services we end up with multiple
                # -> HiddenService instances now (because different
                # -> hostnames)
                clients[name] = AuthenticatedHiddenServiceClient(
                    self, name, hostname,
                    ports=self._ports,
                    token=cookie,
                )
        self._clients = clients
        if self._expected_clients:
            for expected in self._expected_clients:
                if expected not in self._clients:
                    raise RuntimeError(
                        "Didn't find expected client '{}'".format(expected)
                    )

    def config_attributes(self):
        """
        Helper method used by TorConfig when generating a torrc file.
        """

        rtn = [('HiddenServiceDir', str(self._dir))]
        if self._config._supports['HiddenServiceDirGroupReadable'] \
           and self.group_readable:
            rtn.append(('HiddenServiceDirGroupReadable', str(1)))
        for port in self.ports:
            rtn.append(('HiddenServicePort', str(port)))
        if self._version:
            rtn.append(('HiddenServiceVersion', str(self._version)))
        rtn.append((
            'HiddenServiceAuthorizeClient',
            "{} {}".format(self._auth_type, ','.join(self.client_names()))
        ))
        return rtn


def _validate_ports(ports):
    """
    Internal helper.

    Validates the 'ports' argument to EphemeralOnionService or
    EphemeralAuthenticatedOnionService returning None on success or
    raising ValueError otherwise.
    """
    if not isinstance(ports, (list, tuple)):
        raise ValueError("'ports' must be a list of strings")
    if any([not isinstance(x, str) for x in ports]):
        raise ValueError("'ports' must be a list of strings")
    for port in ports:
        if ' ' not in port or len(port.split(' ')) != 2:
            raise ValueError(
                "Port '{}' should have exactly one space in it".format(port)
            )
        (external, internal) = port.split(' ')
        try:
            external = int(external)
        except ValueError:
            raise ValueError(
                "Port '{}' external port isn't an int".format(port)
            )
        if ':' not in internal:
            raise ValueError(
                "Port '{}' local address should be 'IP:port'".format(port)
            )
        ip, localport = internal.split(':')
        from .controller import _is_non_public_numeric_address
        if ip != 'localhost' and not _is_non_public_numeric_address(ip):
            raise ValueError(
                "Port '{}' internal IP '{}' should be a local "
                "address".format(port, ip)
            )


def parse_rsa_blob(lines):
    return 'RSA1024:' + ''.join(lines[1:-1])


def parse_client_keys(stream):
    '''
    This parses a hidden-service "client_keys" file, either stealth or
    basic (they're the same, except "stealth" includes a
    "client-key"). Returns a list of HiddenServiceClientAuth() instances.

    Note that the key does NOT include the "----BEGIN ---" markers,
    nor *any* embedded whitespace. It is *just* the key blob.

    '''

    def parse_error(data):
        raise RuntimeError("Parse error at: " + data)

    class ParserState(object):
        def __init__(self):
            self.keys = []
            self.reset()

        def reset(self):
            self.name = None
            self.cookie = None
            self.key = []

        def create_key(self):
            if self.name is not None:
                self.keys.append(HiddenServiceClientAuth(self.name, self.cookie, self.key))
            self.reset()

        def set_name(self, name):
            self.create_key()
            self.name = name.split()[1]

        def set_cookie(self, cookie):
            self.cookie = cookie.split()[1]
            if self.cookie.endswith('=='):
                self.cookie = self.cookie[:-2]

        def add_key_line(self, line):
            self.key.append(line)

    from txtorcon.spaghetti import FSM, State, Transition
    init = State('init')
    got_name = State('got_name')
    got_cookie = State('got_cookie')
    reading_key = State('got_key')

    parser_state = ParserState()

    # initial state; we want "client-name" or it's an error
    init.add_transitions([
        Transition(got_name, lambda line: line.startswith('client-name '), parser_state.set_name),
        Transition(init, lambda line: not line.startswith('client-name '), parse_error),
    ])

    # next up is "descriptor-cookie" or it's an error
    got_name.add_transitions([
        Transition(got_cookie, lambda line: line.startswith('descriptor-cookie '), parser_state.set_cookie),
        Transition(init, lambda line: not line.startswith('descriptor-cookie '), parse_error),
    ])

    # the "interesting bit": there's either a client-name if we're a
    # "basic" file, or an RSA key (with "client-key" before it)
    got_cookie.add_transitions([
        Transition(reading_key, lambda line: line.startswith('client-key'), None),
        Transition(got_name, lambda line: line.startswith('client-name '), parser_state.set_name),
    ])

    # if we're reading an RSA key, we accumulate it in current_key.key
    # until we hit a line starting with "client-name"
    reading_key.add_transitions([
        Transition(reading_key, lambda line: not line.startswith('client-name'), parser_state.add_key_line),
        Transition(got_name, lambda line: line.startswith('client-name '), parser_state.set_name),
    ])

    # create our FSM and parse the data
    fsm = FSM([init, got_name, got_cookie, reading_key])
    for line in stream.readlines():
        fsm.process(line.strip())

    parser_state.create_key()  # make sure we get the "last" one
    return parser_state.keys


## aliases, that we should deprecate
FilesystemHiddenService = FilesystemOnionService  # XXX
EphemeralHiddenService = EphemeralOnionService  # XXX
