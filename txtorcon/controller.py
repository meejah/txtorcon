# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function
from __future__ import with_statement

from twisted.internet.defer import inlineCallbacks, returnValue


@inlineCallbacks
def launch_tor(config, reactor,
               tor_binary=None,
               progress_updates=None,
               connection_creator=None,
               timeout=None,
               kill_on_stderr=True,
               stdout=None, stderr=None):
    """
    launches a new Tor process with the given config.

    There may seem to be a ton of options, but don't panic: this
    method should be easy to use and most options can be ignored
    except for advanced use-cases. Calling with a completely empty
    TorConfig should Just Work::

        config = TorConfig()
        d = launch_tor(config, reactor)
        d.addCallback(...)

    Note that the incoming TorConfig instance is examined and several
    config options are acted upon appropriately:

    ``DataDirectory``: if supplied, a tempdir is not created, and the
    one supplied is not deleted.

    ``ControlPort``: if 0 (zero), a control connection is NOT
    established (and ``connection_creator`` is ignored). In this case
    we can't wait for Tor to bootstrap, and **you must kill the tor**
    yourself.

    ``User``: if this exists, we attempt to set ownership of the tempdir
    to this user (but only if our effective UID is 0).

    This method may set the following options on the supplied
    TorConfig object: ``DataDirectory, ControlPort,
    CookieAuthentication, __OwningControllerProcess`` and WILL call
    :meth:`txtorcon.TorConfig.save`

    :param config:
        an instance of :class:`txtorcon.TorConfig` with any
        configuration values you want.  If ``ControlPort`` isn't set,
        9052 is used; if ``DataDirectory`` isn't set, tempdir is used
        to create one (in this case, it will be deleted upon exit).

    :param reactor: a Twisted IReactorCore implementation (usually
        twisted.internet.reactor)

    :param tor_binary: path to the Tor binary to run. Tries to find the tor
        binary if unset.

    :param progress_updates: a callback which gets progress updates; gets as
         args: percent, tag, summary (FIXME make an interface for this).

    :param kill_on_stderr:
        When True (the default), if Tor prints anything on stderr we
        kill off the process, close the TorControlProtocol and raise
        an exception.

    :param stdout: a file-like object to which we write anything that
        Tor prints on stdout (just needs to support write()).

    :param stderr: a file-like object to which we write anything that
        Tor prints on stderr (just needs .write()). Note that we kill Tor
        off by default if anything appears on stderr; pass "no_kill=True"
        if you don't like the behavior.

    :param connection_creator: is mostly available to ease testing, so
        you probably don't want to supply this. If supplied, it is a
        callable that should return a Deferred that delivers an
        :api:`twisted.internet.interfaces.IProtocol <IProtocol>` or
        ConnectError.
        See :api:`twisted.internet.interfaces.IStreamClientEndpoint`.connect
        Note that this parameter is ignored if config.ControlPort == 0

    :return: a Deferred which callbacks with :class:`txtorcon.Tor`
        instance, from which you can retrieve the TorControlProtocol
        instance via the ``.protocol`` property.

        In the launched Tor, ``__OwningControllerProcess`` will be set
        and TAKEOWNERSHIP will have been called, so if you close the
        TorControlProtocol the Tor should exit also (see `control-spec
        <https://gitweb.torproject.org/torspec.git/blob/HEAD:/control-spec.txt>`_
        3.23). Note that if ControlPort was 0, we don't connect at all
        and therefore don't wait for Tor to be bootstrapped. In this
        case, it's up to you to kill off the Tor you created.

    HACKS:

     1. It's hard to know when Tor has both (completely!) written its
        authentication cookie file AND is listening on the control
        port. It seems that waiting for the first 'bootstrap' message on
        stdout is sufficient. Seems fragile...and doesn't work 100% of
        the time, so FIXME look at Tor source.
    """

    # We have a slight problem with the approach: we need to pass a
    # few minimum values to a torrc file so that Tor will start up
    # enough that we may connect to it. Ideally, we'd be able to
    # start a Tor up which doesn't really do anything except provide
    # "AUTHENTICATE" and "GETINFO config/names" so we can do our
    # config validation.

    # the other option here is to simply write a torrc version of our
    # config and get Tor to load that...which might be the best
    # option anyway.

    # actually, can't we pass them all as command-line arguments?
    # could be pushing some limits for giant configs...

    if tor_binary is None:
        tor_binary = find_tor_binary()
    if tor_binary is None:
        # We fail right here instead of waiting for the reactor to start
        raise TorNotFound('Tor binary could not be found')

    # make sure we got things that have write() for stderr, stdout
    # kwargs
    for arg in [stderr, stdout]:
        if arg and not getattr(arg, "write", None):
            raise RuntimeError(
                'File-like object needed for stdout or stderr args.'
            )

    try:
        data_directory = config.DataDirectory
        user_set_data_directory = True
    except KeyError:
        user_set_data_directory = False
        data_directory = tempfile.mkdtemp(prefix='tortmp')
        config.DataDirectory = data_directory

        # Set ownership on the temp-dir to the user tor will drop privileges to
        # when executing as root.
        try:
            user = config.User
        except KeyError:
            pass
        else:
            if sys.platform in ('linux2', 'darwin') and os.geteuid() == 0:
                os.chown(data_directory, pwd.getpwnam(user).pw_uid, -1)

    try:
        control_port = config.ControlPort
    except KeyError:
        control_port = yield available_tcp_port()
        config.ControlPort = control_port

    # so, we support passing in ControlPort=0 -- not really sure if
    # this is a good idea (since then the caller has to kill the tor
    # off, etc), but at least one person has requested its :/
    if control_port != 0:
        config.CookieAuthentication = 1
        config.__OwningControllerProcess = os.getpid()
        if connection_creator is None:
            connection_creator = functools.partial(
                TCP4ClientEndpoint(reactor, 'localhost', control_port).connect,
                TorProtocolFactory()
            )
    else:
        connection_creator = None

    # NOTE well, that if we don't pass "-f" then Tor will merrily load
    # its default torrc, and apply our options over top... :/
    config_args = ['-f', '/non-existant', '--ignore-missing-torrc']

    # ...now add all our config options on the command-line. This
    # avoids writing a temporary torrc.
    for (k, v) in config.config_args():
        config_args.append(k)
        config_args.append(v)

    # txtorlog.msg('Running with config:\n', ' '.join(config_args))

    process_protocol = TorProcessProtocol(
        connection_creator,
        progress_updates,
        config, reactor,
        timeout,
        kill_on_stderr,
        stdout,
        stderr
    )

    # we set both to_delete and the shutdown events because this
    # process might be shut down way before the reactor, but if the
    # reactor bombs out without the subprocess getting closed cleanly,
    # we'll want the system shutdown events triggered so the temporary
    # files get cleaned up either way

    # we don't want to delete the user's directories, just temporary
    # ones this method created.
    if not user_set_data_directory:
        process_protocol.to_delete = [data_directory]
        reactor.addSystemEventTrigger(
            'before', 'shutdown',
            functools.partial(delete_file_or_tree, data_directory)
        )

    try:
        log.msg('Spawning tor process with DataDirectory', data_directory)
        args = [tor_binary] + config_args
        transport = reactor.spawnProcess(
            process_protocol,
            tor_binary,
            args=args,
            env={'HOME': data_directory},
            path=data_directory
        )
        # FIXME? don't need rest of the args: uid, gid, usePTY, childFDs)
        transport.closeStdin()

    except RuntimeError:
        # XXX if we can indeed just let this out, take out the
        # try/except
        raise

    if process_protocol.connected_cb:
        yield process_protocol.connected_cb

    tor = Tor(reactor, process_protocol.tor_protocol, _process)


def connect(control_endpoint, password_function=None):
    """
    XXX THINK: do we want/need a reactor arg?
    The creates a :class:`txtorcon.Tor` instance by connecting to an
    already-running tor's control port. For example, a common default
    for tor is UNIXClientEndpoint(reactor, '/var/run/tor/control') or
    TCP4ClientEndpoint(reactor, 'localhost', 9051)

    If only password authentication is available in the client, the
    ``password_function`` is called (if supplied) to retrieve a valid
    password. This function can return a Deferred.

    For example::

        import txtorcon
        from twisted.internet.task import react
        from twisted.internet.defer import inlineCallbacks

        @inlineCallbacks
        def main(reactor):
            tor = yield txtorcon.connect(
                TCP4ClientEndpoint(reactor, "localhost", 9051)
            )
            state = yield tor.create_state()
            for circuit in state.circuits:
                print(circuit)

    :param password_function:
        See :class:`txtorcon.TorControlProtocol`

    :return:
        a Deferred that fires with a :class:`txtorcon.Tor` instance
    """

    if not IStreamClientEndpoint.providedBy(control_endpoint):
        raise ValueError("control_endpoint must provide IStreamClientEndpoint")

    proto = yield control_endpoint.connect(
        TorProtocolFactory(
            password_function=password_function
        )
    )
    yield proto.post_bootstrap
    returnValue(proto)


class Tor(object):
    """
    I represent a single instance of Tor and act as a Builder/Factory
    for several useful objects you will probably want. There are two
    ways to create a Tor instance:

       - :func:`txtorcon.connect`` to connect to a tor that is already
         running (e.g. Tor Browser Bundle, a system Tor, ...).
       - :func:`txtorcon.launch`` to launch a fresh tor instance

    If you desire more control, there are "lower level" APIs which are
    the very ones used by this class. However, this "highest level"
    API should cover many use-cases::

        import txtorcon

        @inlineCallbacks
        def main(reactor):
            # tor = yield txtorcon.connect(UNIXClientEndpoint(reactor, "/var/run/tor/control"))
            tor = yield txtorcon.launch(reactor)

            onion_ep = tor.create_onion_endpoint(port=80)
            port = yield onion_ep.listen(Site())
            print(port.getHost())
    """

    def __init__(self, reactor, tor_control_protocol, _process_proto=None):
        """
        (mostly) don't instantiate this class yourself -- instead use the
        factory methods :func:`txtorcon.launch` or :func:`txtorcon.connect`
        """
        self._protocol = tor_control_protocol
        self._reactor = reactor
        # this only passed/set when we launch()
        self._process_protocol = _process_proto

    @property
    def protocol(self):
        """
        The TorControlProtocol instance that is communicating with this
        Tor instance.
        """
        return self._protocol

    # XXX One Onion Method To Rule Them All, or
    # create_disk_onion_endpoint vs. create_ephemeral_onion_endpoint,
    # or ...?
    def create_onion_endpoint(self, port, private_key=None, hs_dir=None, ):
        """
        for "real" args, see onion.py in the hidden-services API branch
        """
        raise NotImplemented(__name__)

    def create_client_endpoint(self, host, port, ...):
        """
        returns an IStreamClientEndpoint instance that will connect via
        SOCKS over this Tor instance. Error if this Tor has no SOCKS
        ports.
        """
        # probably takes args similar to TorClientEndpoint on master
        return IEndpoint()

    @inlineCallbacks
    def create_state(self):
        # fires with TorState instance
        state = TorState(self.protocol)
        yield state._post_bootstrap
        returnValue(state)

    def create_config(self):
        # fires with TorConfig instance
        return Deferred()

    def shutdown(self):
        # shuts down the Tor instance; nothing else will work after this

    # XXX idea-time, could make this a context-manager so that you can
    # do something like:
    #    with Tor.launch(...) as tor:
    #        tor.client_endpoint('torproject.org', 443)
    #    # Tor instance now shutdown etc.
    # hmm, actually that's maybe a bad idea as launch() is async so you'd need:
    # tor = yield Tor.launch()
    # with tor:
    #    tor.client_endpoint('torproject.org', 443)
    def __enter__(self):
        return self
    def __exit__(self, a, b, c):
        self.shutdown()
