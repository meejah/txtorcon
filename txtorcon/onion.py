import tempfile

from twisted.internet import defer

from txtorcon.torconfig import HiddenService
from txtorcon.torconfig import EphemeralHiddenService
from txtorcon.endpoints import TCPHiddenServiceEndpoint

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

@defer.inlineCallbacks
def create_onion_service(
        reactor, torconfig, ports,
        directory=None,
        private_key=None,
        ephemeral=True,
        detach=None,
        discard_key=None,
        auth_type='none',
        await_upload=True):
    """
    This yields a new IOnionService if ``auth_type`` is "none" (the
    defalt) otherwise yields an IAuthenticatdOnionService (if
    ``auth_type`` is "basic" or "stealth"). In either case, the
    Deferred returned only fires once Tor has been configured *and* at
    least one descriptor has been successfully uploaded.

    :param ports: a list of "ports" lines (str), which look like: ``80
        127.0.0.1:1234`` or more generally ``public_port
        host:local_port`` (XXX what about unix sockets?)
    :type ports: list of str

    :param directory: the directory to use that contains `hostname`
        and ``private_key`` files. If one is not suppied, it will be created
        (honoring ``$TMPDIR``, if set)
    :type directory: str

    :param ephemeral: If True, uses ADD_ONION command; otherwise, uses
        the HiddenServiceDir configuration option (and creates/uses a
        temporary or permanent directory to pass private keys to/from
        Tor.  Note that ADD_ONION doesn't yet allow passing any
        authentication options, so this is only allowed if auth_type
        == "none"
    :type ephemeral: bool

    :param auth_type: 'basic' (the default) or 'stealth'
    :type auth_type: str

    :param await_upload: if True (the default) wait for at least one
        descriptor upload to succeed before the callback fires. The hidden
        service will not be reachable by any clients until 1 or more
        descriptors are uploaded.
    :type await_upload: bool
    """
    # validate args
    acceptable_auth = ['none', 'basic', 'stealth']
    if auth_type not in acceptable_auth:
        raise ValueError(
            "auth_type must be one of: {}".format(
                ", ".join(acceptable_auth),
            )
        )
    if auth_type != "none" and ephemeral:
        raise ValueError(
            "ephemeral onion services only work with auth_type='none'"
        )

    if ephemeral:
        detach = bool(detach)  # False by default
        discard_key = bool(discard_key)  # False by default
    else:
        if detach is not None:
            raise ValueError(
                "'detach' can only be specified for ephemeral services"
            )
        if discard_key is not None:
            raise ValueError(
                "'discard_key' can only be specified for ephemeral services"
            )

    # there are the following types of hidden/onion services we can
    # create:
    # ephemeral:
    #   - no auth -> EphemeralHiddenService instance
    # filesystem:
    #   - no auth -> HiddenService instance
    #   - basic auth -> AuthenticatedHiddenService instance
    #   - stealth auth -> AuthenticatdHiddenService instance
    # So, "onion" wil be one of the above after this "case" statement

    if auth_type == 'none':
        if ephemeral:
            hs = yield EphemeralHiddenService.create(
                torconfig, ports,
                detach=detach,
                discard_key=discard_key,
            )
            defer.returnValue(hs)
            return

        else:
            if directory is None:
                # XXX when to delete this?
                directory = tempfile.mkdtemp()
                print("MADE", directory)

            hs = HiddenService(
                torconfig, directory, ports,
            )
            torconfig.HiddenServices.append(hs)
            # listen for the descriptor upload event
            info_callback = defer.Deferred()

            def info_event(msg):
                # XXX giant hack here; Right Thing would be to implement a
                # "real" event in Tor and listen for that.
                if 'Service descriptor (v2) stored' in msg:
                    info_callback.callback(None)
            torconfig.protocol.add_event_listener('INFO', info_event)

            yield torconfig.save()
            yield info_callback  # awaits an INFO log-line from Tor .. sketchy
            torconfig.protocol.remove_event_listener('INFO', info_event)

            print("DING", hs)
            defer.returnValue(hs)
            return

    elif auth_type == 'basic':
        raise NotImplementedError()
    elif auth_type == 'stealth':
        raise NotImplementedError()

