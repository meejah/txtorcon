# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function
from __future__ import with_statement

import os
import sys
import six
import shlex
import tempfile
import functools
import ipaddress
from io import StringIO
from collections import Sequence
from os.path import dirname, exists

from twisted.python import log
from twisted.python.failure import Failure
from twisted.internet.defer import inlineCallbacks, returnValue, Deferred, succeed, fail
from twisted.internet import protocol, error
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.endpoints import UNIXClientEndpoint
from twisted.internet.interfaces import IReactorTime, IReactorCore
from twisted.internet.interfaces import IStreamClientEndpoint

from zope.interface import implementer

from txtorcon.util import delete_file_or_tree, find_keywords
from txtorcon.util import find_tor_binary, available_tcp_port
from txtorcon.log import txtorlog
from txtorcon.torcontrolprotocol import TorProtocolFactory
from txtorcon.torstate import TorState
from txtorcon.torconfig import TorConfig
from txtorcon.endpoints import TorClientEndpoint, _create_socks_endpoint
from . import socks
from .interface import ITor

if sys.platform in ('linux', 'linux2', 'darwin'):
    import pwd


@inlineCallbacks
def launch(reactor,
           progress_updates=None,
           control_port=None,
           data_directory=None,
           socks_port=None,
           stdout=None,
           stderr=None,
           timeout=None,
           tor_binary=None,
           user=None,  # XXX like the config['User'] special-casing from before
           # 'users' probably never need these:
           connection_creator=None,
           kill_on_stderr=True,
           _tor_config=None,  # a TorConfig instance, mostly for tests
           ):
    """
    launches a new Tor process, and returns a Deferred that fires with
    a new :class:`txtorcon.Tor` instance. From this instance, you can
    create or get any "interesting" instances you need: the
    :class:`txtorcon.TorConfig` instance, create endpoints, create
    :class:`txtorcon.TorState` instance(s), etc.

    Note that there is NO way to pass in a config; we only expost a
    couple of basic Tor options. If you need anything beyond these,
    you can access the ``TorConfig`` instance (via ``.config``)
    and make any changes there, reflecting them in tor with
    ``.config.save()``.

    You can igore all the options and safe defaults will be
    provided. However, **it is recommended to pass data_directory**
    especially if you will be starting up Tor frequently, as it saves
    a bunch of time (and bandwidth for the directory
    authorities). "Safe defaults" means:

      - a tempdir for a ``DataDirectory`` is used (respecting ``TMP``)
        and is deleted when this tor is shut down (you therefore
        *probably* want to supply the ``data_directory=`` kwarg);
      - a random, currently-unused local TCP port is used as the
        ``SocksPort`` (specify ``socks_port=`` if you want your
        own). If you want no SOCKS listener at all, pass
        ``socks_port=0``
      - we set ``__OwningControllerProcess`` and call
        ``TAKEOWNERSHIP`` so that if our control connection goes away,
        tor shuts down (see `control-spec
        <https://gitweb.torproject.org/torspec.git/blob/HEAD:/control-spec.txt>`_
        3.23).
      - the launched Tor will use ``COOKIE`` authentication.

    :param reactor: a Twisted IReactorCore implementation (usually
        twisted.internet.reactor)

    :param progress_updates: a callback which gets progress updates; gets 3
         args: percent, tag, summary (FIXME make an interface for this).

    :param data_directory: set as the ``DataDirectory`` option to Tor,
        this is where tor keeps its state information (cached relays,
        etc); starting with an already-populated state directory is a lot
        faster. If ``None`` (the default), we create a tempdir for this
        **and delete it on exit**. It is recommended you pass something here.

    :param stdout: a file-like object to which we write anything that
        Tor prints on stdout (just needs to support write()).

    :param stderr: a file-like object to which we write anything that
        Tor prints on stderr (just needs .write()). Note that we kill
        Tor off by default if anything appears on stderr; pass
        "kill_on_stderr=False" if you don't want this behavior.

    :param tor_binary: path to the Tor binary to run. If None (the
        default), we try to find the tor binary.

    :param kill_on_stderr:
        When True (the default), if Tor prints anything on stderr we
        kill off the process, close the TorControlProtocol and raise
        an exception.

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

    HACKS:

     1. It's hard to know when Tor has both (completely!) written its
        authentication cookie file AND is listening on the control
        port. It seems that waiting for the first 'bootstrap' message on
        stdout is sufficient. Seems fragile...and doesn't work 100% of
        the time, so FIXME look at Tor source.



    XXX this "User" thing was, IIRC, a feature for root-using scripts
    (!!) that were going to launch tor, but where tor would drop to a
    different user. Do we still want to support this? Probably
    relevant to Docker (where everything is root! yay!)

    ``User``: if this exists, we attempt to set ownership of the tempdir
    to this user (but only if our effective UID is 0).
    """

    # We have a slight problem with the approach: we need to pass a
    # few minimum values to a torrc file so that Tor will start up
    # enough that we may connect to it. Ideally, we'd be able to
    # start a Tor up which doesn't really do anything except provide
    # "AUTHENTICATE" and "GETINFO config/names" so we can do our
    # config validation.

    if not IReactorCore.providedBy(reactor):
        raise ValueError(
            "'reactor' argument must provide IReactorCore"
            " (got '{}': {})".format(
                type(reactor).__class__.__name__,
                repr(reactor)
            )
        )

    if tor_binary is None:
        tor_binary = find_tor_binary()
    if tor_binary is None:
        # We fail right here instead of waiting for the reactor to start
        raise TorNotFound('Tor binary could not be found')

    # make sure we got things that have write() for stderr, stdout
    # kwargs (XXX is there a "better" way to check for file-like object?)
    for arg in [stderr, stdout]:
        if arg and not getattr(arg, "write", None):
            raise RuntimeError(
                'File-like object needed for stdout or stderr args.'
            )

    config = _tor_config or TorConfig()
    if data_directory is not None:
        user_set_data_directory = True
        config.DataDirectory = data_directory
        try:
            os.mkdir(data_directory, 0o0700)
        except OSError:
            pass
    else:
        user_set_data_directory = False
        data_directory = tempfile.mkdtemp(prefix='tortmp')
        config.DataDirectory = data_directory
        # note: we also set up the ProcessProtocol to delete this when
        # Tor exits, this is "just in case" fallback:
        reactor.addSystemEventTrigger(
            'before', 'shutdown',
            functools.partial(delete_file_or_tree, data_directory)
        )

    # things that used launch_tor() had to set ControlPort and/or
    # SocksPort on the config to pass them, so we honour that here.
    if control_port is None and _tor_config is not None:
        try:
            control_port = config.ControlPort
        except KeyError:
            control_port = None

    if socks_port is None and _tor_config is not None:
        try:
            socks_port = config.SocksPort
        except KeyError:
            socks_port = None

    if socks_port is None:
        socks_port = yield available_tcp_port(reactor)
    config.SOCKSPort = socks_port

    try:
        our_user = user or config.User
    except KeyError:
        pass
    else:
        if sys.platform in ('linux', 'linux2', 'darwin') and os.geteuid() == 0:
            os.chown(data_directory, pwd.getpwnam(our_user).pw_uid, -1)

    # user can pass in a control port, or we set one up here
    if control_port is None:
        # on posix-y systems, we can use a unix-socket
        if sys.platform in ('linux', 'linux2', 'darwin'):
            # note: tor will not accept a relative path for ControlPort
            control_port = 'unix:{}'.format(
                os.path.join(os.path.realpath(data_directory), 'control.socket')
            )
        else:
            control_port = yield available_tcp_port(reactor)
    else:
        if str(control_port).startswith('unix:'):
            control_path = control_port.lstrip('unix:')
            containing_dir = dirname(control_path)
            if not exists(containing_dir):
                raise ValueError(
                    "The directory containing '{}' must exist".format(
                        containing_dir
                    )
                )
            # Tor will be sad if the directory isn't 0700
            mode = (0o0777 & os.stat(containing_dir).st_mode)
            if mode & ~(0o0700):
                raise ValueError(
                    "The directory containing a unix control-socket ('{}') "
                    "must only be readable by the user".format(containing_dir)
                )
    config.ControlPort = control_port

    config.CookieAuthentication = 1
    config.__OwningControllerProcess = os.getpid()
    if connection_creator is None:
        if str(control_port).startswith('unix:'):
            connection_creator = functools.partial(
                UNIXClientEndpoint(reactor, control_port[5:]).connect,
                TorProtocolFactory()
            )
        else:
            connection_creator = functools.partial(
                TCP4ClientEndpoint(reactor, 'localhost', control_port).connect,
                TorProtocolFactory()
            )
    # not an "else" on purpose; if we passed in "control_port=0" *and*
    # a custom connection creator, we should still set this to None so
    # it's never called (since we can't connect with ControlPort=0)
    if control_port == 0:
        connection_creator = None

    # NOTE well, that if we don't pass "-f" then Tor will merrily load
    # its default torrc, and apply our options over top... :/ should
    # file a bug probably? --no-defaults or something maybe? (does
    # --defaults-torrc - or something work?)
    config_args = ['-f', '/dev/null/non-existant-on-purpose', '--ignore-missing-torrc']

    # ...now add all our config options on the command-line. This
    # avoids writing a temporary torrc.
    for (k, v) in config.config_args():
        config_args.append(k)
        config_args.append(v)

    process_protocol = TorProcessProtocol(
        connection_creator,
        progress_updates,
        config, reactor,
        timeout,
        kill_on_stderr,
        stdout,
        stderr,
    )
    if control_port == 0:
        connected_cb = succeed(None)
    else:
        connected_cb = process_protocol.when_connected()

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

    log.msg('Spawning tor process with DataDirectory', data_directory)
    args = [tor_binary] + config_args
    # XXX note to self; we create data_directory above, so when this
    # is master we can close
    # https://github.com/meejah/txtorcon/issues/178
    transport = reactor.spawnProcess(
        process_protocol,
        tor_binary,
        args=args,
        env={'HOME': data_directory},
        path=data_directory if os.path.exists(data_directory) else None,  # XXX error if it doesn't exist?
    )
    # FIXME? don't need rest of the args: uid, gid, usePTY, childFDs)
    transport.closeStdin()
    proto = yield connected_cb
    # note "proto" here is a TorProcessProtocol

    # we might need to attach this protocol to the TorConfig
    if config.protocol is None and proto is not None and proto.tor_protocol is not None:
        # proto is None in the ControlPort=0 case
        yield config.attach_protocol(proto.tor_protocol)
        # note that attach_protocol waits for the protocol to be
        # boostrapped if necessary

    returnValue(
        Tor(
            reactor,
            config.protocol,
            _tor_config=config,
            _process_proto=process_protocol,
        )
    )


# XXX
# what about control_endpoint_or_endpoints? (i.e. allow a list to try?)
# what about if it's None (default?) and we try some candidates?

@inlineCallbacks
def connect(reactor, control_endpoint=None, password_function=None):
    """
    Creates a :class:`txtorcon.Tor` instance by connecting to an
    already-running tor's control port. For example, a common default
    tor uses is UNIXClientEndpoint(reactor, '/var/run/tor/control') or
    TCP4ClientEndpoint(reactor, 'localhost', 9051)

    If only password authentication is available in the tor we connect
    to, the ``password_function`` is called (if supplied) to retrieve
    a valid password. This function can return a Deferred.

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

    :param control_endpoint: None, an IStreamClientEndpoint to connect
        to, or a Sequence of IStreamClientEndpoint instances to connect
        to. If None, a list of defaults are tried.

    :param password_function:
        See :class:`txtorcon.TorControlProtocol`

    :return:
        a Deferred that fires with a :class:`txtorcon.Tor` instance
    """

    @inlineCallbacks
    def try_endpoint(control_ep):
        assert IStreamClientEndpoint.providedBy(control_ep)
        proto = yield control_ep.connect(
            TorProtocolFactory(
                password_function=password_function
            )
        )
        config = yield TorConfig.from_protocol(proto)
        tor = Tor(reactor, proto, _tor_config=config)
        returnValue(tor)

    if control_endpoint is None:
        to_try = [
            UNIXClientEndpoint(reactor, '/var/run/tor/control'),
            TCP4ClientEndpoint(reactor, '127.0.0.1', 9051),
            TCP4ClientEndpoint(reactor, '127.0.0.1', 9151),
        ]
    elif IStreamClientEndpoint.providedBy(control_endpoint):
        to_try = [control_endpoint]
    elif isinstance(control_endpoint, Sequence):
        to_try = control_endpoint
        for ep in control_endpoint:
            if not IStreamClientEndpoint.providedBy(ep):
                raise ValueError(
                    "For control_endpoint=, '{}' must provide"
                    " IStreamClientEndpoint".format(ep)
                )
    else:
        raise ValueError(
            "For control_endpoint=, '{}' must provide"
            " IStreamClientEndpoint".format(control_endpoint)
        )

    errors = []
    for idx, ep in enumerate(to_try):
        try:
            tor = yield try_endpoint(ep)
            txtorlog.msg("Connected via '{}'".format(ep))
            returnValue(tor)
        except Exception as e:
            errors.append(e)
    if len(errors) == 1:
        raise errors[0]
    raise RuntimeError(
        'Failed to connect to: {}'.format(
            ', '.join(
                '{}: {}'.format(ep, err) for ep, err in zip(to_try, errors)
            )
        )
    )


@implementer(ITor)
class Tor(object):
    """
    I represent a single instance of Tor and act as a Builder/Factory
    for several useful objects you will probably want. There are two
    ways to create a Tor instance:

       - :func:`txtorcon.connect` to connect to a Tor that is already
         running (e.g. Tor Browser Bundle, a system Tor, ...).
       - :func:`txtorcon.launch` to launch a fresh Tor instance

    The stable API provided by this class is :class:`txtorcon.interface.ITor`

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

    def __init__(self, reactor, control_protocol, _tor_config=None, _process_proto=None):
        """
        don't instantiate this class yourself -- instead use the factory
        methods :func:`txtorcon.launch` or :func:`txtorcon.connect`
        """
        self._protocol = control_protocol
        self._config = _tor_config
        self._reactor = reactor
        # this only passed/set when we launch()
        self._process_protocol = _process_proto
        # cache our preferred socks port (please use
        # self._default_socks_endpoint() to get one)
        self._socks_endpoint = None

    @inlineCallbacks
    def quit(self):
        """
        Closes the control connection, and if we launched this Tor
        instance we'll send it a TERM and wait until it exits.
        """
        if self._protocol is not None:
            yield self._protocol.quit()
        if self._process_protocol is not None:
            yield self._process_protocol.quit()
        if self._protocol is None and self._process_protocol is None:
            raise RuntimeError(
                "This Tor has no protocol instance; we can't quit"
            )

    # XXX bikeshed on this name?
    @property
    def process(self):
        if self._process_protocol:
            return self._process_protocol
        raise RuntimeError(
            "This Tor instance was not launched by us; no process to return"
        )

    @property
    def protocol(self):
        """
        The TorControlProtocol instance that is communicating with this
        Tor instance.
        """
        return self._protocol

    @property
    def version(self):
        return self._protocol.version

    @inlineCallbacks
    def get_config(self):
        """
        :return: a Deferred that fires with a TorConfig instance. This
            instance represents up-to-date configuration of the tor
            instance (even if another controller is connected). If you
            call this more than once you'll get the same TorConfig back.
        """
        if self._config is None:
            self._config = yield TorConfig.from_protocol(self._protocol)
        returnValue(self._config)

    @inlineCallbacks
    def create_v3_onion_service(self, *args, **kw):
        # FIXME if I keep anything like this, explicitly pass args probably
        config = yield self.get_config()
        from txtorcon import onion
        kw['version'] = 3
        hs = yield onion.FilesystemHiddenService.create(config, *args, **kw)
        returnValue(hs)

    def web_agent(self, pool=None, socks_endpoint=None):
        """
        :param socks_endpoint: If ``None`` (the default), a suitable
            SOCKS port is chosen from our config (or added). If supplied,
            should be a Deferred which fires an IStreamClientEndpoint
            (e.g. the return-value from
            :meth:`txtorcon.TorConfig.socks_endpoint`) or an immediate
            IStreamClientEndpoint You probably don't need to mess with
            this.

        :param pool: passed on to the Agent (as ``pool=``)
        """
        # local import since not all platforms have this
        from txtorcon import web

        if socks_endpoint is None:
            socks_endpoint = _create_socks_endpoint(self._reactor, self._protocol)
        if not isinstance(socks_endpoint, Deferred):
            if not IStreamClientEndpoint.providedBy(socks_endpoint):
                raise ValueError(
                    "'socks_endpoint' should be a Deferred or an IStreamClient"
                    "Endpoint (got '{}')".format(type(socks_endpoint))
                )
        return web.tor_agent(
            self._reactor,
            socks_endpoint,
            pool=pool,
        )

    @inlineCallbacks
    def dns_resolve(self, hostname):
        """
        :param hostname: a string

        :returns: a Deferred that calbacks with the hostname as looked-up
            via Tor (or errback).  This uses Tor's custom extension to the
            SOCKS5 protocol.
        """
        socks_ep = yield self._default_socks_endpoint()
        ans = yield socks.resolve(socks_ep, hostname)
        returnValue(ans)

    @inlineCallbacks
    def dns_resolve_ptr(self, ip):
        """
        :param ip: a string, like "127.0.0.1"

        :returns: a Deferred that calbacks with the IP address as
            looked-up via Tor (or errback).  This uses Tor's custom
            extension to the SOCKS5 protocol.
        """
        socks_ep = yield self._default_socks_endpoint()
        ans = yield socks.resolve_ptr(socks_ep, ip)
        returnValue(ans)

    def stream_via(self, host, port, tls=False, socks_endpoint=None):
        """
        This returns an IStreamClientEndpoint_ instance that will use this
        Tor (via SOCKS) to visit the ``(host, port)`` indicated.

        :param host: The host to connect to. You MUST pass host-names
            to this. If you absolutely know that you've not leaked DNS
            (e.g. you save IPs in your app's configuration or similar)
            then you can pass an IP.

        :param port: Port to connect to.

        :param tls: If True, it will wrap the return endpoint in one
            that does TLS (default: False).

        :param socks_endpoint: Normally not needed (default: None)
            but you can pass an IStreamClientEndpoint_ directed at one
            of the local Tor's SOCKS5 ports (e.g. created with
            :meth:`txtorcon.TorConfig.create_socks_endpoint`). Can be
            a Deferred.

        .. _IStreamClientEndpoint: https://twistedmatrix.com/documents/current/api/twisted.internet.interfaces.IStreamClientEndpoint.html
        """
        if _is_non_public_numeric_address(host):
            raise ValueError("'{}' isn't going to work over Tor".format(host))

        if socks_endpoint is None:
            socks_endpoint = self._default_socks_endpoint()
        # socks_endpoint may be a a Deferred, but TorClientEndpoint handles it
        return TorClientEndpoint(
            host, port,
            socks_endpoint=socks_endpoint,
            tls=tls,
            reactor=self._reactor,
        )

    # XXX note to self: insert onion endpoint-creation functions when
    # merging onion.py

    # XXX or get_state()? and make there be always 0 or 1 states; cf. convo w/ Warner
    @inlineCallbacks
    def create_state(self):
        """
        returns a Deferred that fires with a ready-to-go
        :class:`txtorcon.TorState` instance.
        """
        state = TorState(self.protocol)
        yield state.post_bootstrap
        returnValue(state)

    def __str__(self):
        return "<Tor version='{tor_version}'>".format(
            tor_version=self._protocol.version,
        )

    @inlineCallbacks
    def is_ready(self):
        """
        :return: a Deferred that fires with True if this Tor is
            non-dormant and ready to go. This will return True if `GETINFO
            dormant` is false or if `GETINFO status/enough-dir-info` is
            true or if `GETINFO status/circuit-established` true.
        """
        info = yield self.protocol.get_info(
            "dormant",
            "status/enough-dir-info",
            "status/circuit-established",
        )
        returnValue(
            not(
                int(info["dormant"]) or
                not int(info["status/enough-dir-info"]) or
                not int(info["status/circuit-established"])
            )
        )

    @inlineCallbacks
    def become_ready(self):
        """
        Make sure Tor is no longer dormant.

        If Tor is currently dormant, it is woken up by doing a DNS
        request for torproject.org
        """
        ready = yield self.is_ready()
        if not ready:
            yield self.dns_resolve(u'torproject.org')
        return

    @inlineCallbacks
    def _default_socks_endpoint(self):
        """
        Returns a Deferred that fires with our default SOCKS endpoint
        (which might mean setting one up in our attacked Tor if it
        doesn't have one)
        """
        if self._socks_endpoint is None:
            self._socks_endpoint = yield _create_socks_endpoint(self._reactor, self._protocol)
        returnValue(self._socks_endpoint)


# XXX from magic-wormhole
def _is_non_public_numeric_address(host):
    # for numeric hostnames, skip RFC1918 addresses, since no Tor exit
    # node will be able to reach those. Likewise ignore IPv6 addresses.
    try:
        a = ipaddress.ip_address(six.text_type(host))
    except ValueError:
        return False        # non-numeric, let Tor try it
    if a.is_loopback or a.is_multicast or a.is_private or a.is_reserved \
       or a.is_unspecified:
        return True         # too weird, don't connect
    return False


class TorNotFound(RuntimeError):
    """
    Raised by launch_tor() in case the tor binary was unspecified and could
    not be found by consulting the shell.
    """


class TorProcessProtocol(protocol.ProcessProtocol):

    def __init__(self, connection_creator, progress_updates=None, config=None,
                 ireactortime=None, timeout=None, kill_on_stderr=True,
                 stdout=None, stderr=None):
        """
        This will read the output from a Tor process and attempt a
        connection to its control port when it sees any 'Bootstrapped'
        message on stdout. You probably don't need to use this
        directly except as the return value from the
        :func:`txtorcon.launch_tor` method. tor_protocol contains a
        valid :class:`txtorcon.TorControlProtocol` instance by that
        point.

        connection_creator is a callable that should return a Deferred
        that callbacks with a :class:`txtorcon.TorControlProtocol`;
        see :func:`txtorcon.launch_tor` for the default one which is a
        functools.partial that will call
        ``connect(TorProtocolFactory())`` on an appropriate
        :api:`twisted.internet.endpoints.TCP4ClientEndpoint`

        :param connection_creator: A no-parameter callable which
            returns a Deferred which promises a
            :api:`twisted.internet.interfaces.IStreamClientEndpoint
            <IStreamClientEndpoint>`. If this is None, we do NOT
            attempt to connect to the underlying Tor process.

        :param progress_updates: A callback which received progress
            updates with three args: percent, tag, summary

        :param config: a TorConfig object to connect to the
            TorControlProtocl from the launched tor (should it succeed)

        :param ireactortime:
            An object implementing IReactorTime (i.e. a reactor) which
            needs to be supplied if you pass a timeout.

        :param timeout:
            An int representing the timeout in seconds. If we are
            unable to reach 100% by this time we will consider the
            setting up of Tor to have failed. Must supply ireactortime
            if you supply this.

        :param kill_on_stderr:
            When True, kill subprocess if we receive anything on stderr

        :param stdout:
            Anything subprocess writes to stdout is sent to .write() on this

        :param stderr:
            Anything subprocess writes to stderr is sent to .write() on this

        :ivar tor_protocol: The TorControlProtocol instance connected
            to the Tor this
            :api:`twisted.internet.protocol.ProcessProtocol
            <ProcessProtocol>`` is speaking to. Will be valid after
            the Deferred returned from
            :meth:`TorProcessProtocol.when_connected` is triggered.
        """

        self.config = config
        self.tor_protocol = None
        self.progress_updates = progress_updates

        # XXX if connection_creator is not None .. is connected_cb
        # tied to connection_creator...?
        if connection_creator:
            self.connection_creator = connection_creator
        else:
            self.connection_creator = None
        # use SingleObserver
        self._connected_listeners = []  # list of Deferred (None when we're connected)

        self.attempted_connect = False
        self.to_delete = []
        self.kill_on_stderr = kill_on_stderr
        self.stderr = stderr
        self.stdout = stdout
        self.collected_stdout = StringIO()

        self._setup_complete = False
        self._did_timeout = False
        self._timeout_delayed_call = None
        self._on_exit = []  # Deferred's we owe a call/errback to when we exit
        if timeout:
            if not ireactortime:
                raise RuntimeError(
                    'Must supply an IReactorTime object when supplying a '
                    'timeout')
            ireactortime = IReactorTime(ireactortime)
            self._timeout_delayed_call = ireactortime.callLater(
                timeout, self._timeout_expired)

    def when_connected(self):
        if self._connected_listeners is None:
            return succeed(self)
        d = Deferred()
        self._connected_listeners.append(d)
        return d

    def _maybe_notify_connected(self, arg):
        """
        Internal helper.

        .callback or .errback on all Deferreds we've returned from
        `when_connected`
        """
        if self._connected_listeners is None:
            return
        for d in self._connected_listeners:
            # Twisted will turn this into an errback if "arg" is a
            # Failure
            d.callback(arg)
        self._connected_listeners = None

    def quit(self):
        """
        This will terminate (with SIGTERM) the underlying Tor process.

        :returns: a Deferred that callback()'s (with None) when the
            process has actually exited.
        """

        try:
            self.transport.signalProcess('TERM')
            d = Deferred()
            self._on_exit.append(d)

        except error.ProcessExitedAlready:
            self.transport.loseConnection()
            d = succeed(None)
        except Exception:
            d = fail()
        return d

    def _signal_on_exit(self, reason):
        to_notify = self._on_exit
        self._on_exit = []
        for d in to_notify:
            d.callback(None)

    def outReceived(self, data):
        """
        :api:`twisted.internet.protocol.ProcessProtocol <ProcessProtocol>` API
        """

        if self.stdout:
            self.stdout.write(data.decode('ascii'))

        # minor hack: we can't try this in connectionMade because
        # that's when the process first starts up so Tor hasn't
        # opened any ports properly yet. So, we presume that after
        # its first output we're good-to-go. If this fails, we'll
        # reset and try again at the next output (see this class'
        # tor_connection_failed)
        txtorlog.msg(data)
        if not self.attempted_connect and self.connection_creator \
                and b'Bootstrap' in data:
            self.attempted_connect = True
            # hmmm, we don't "do" anything with this Deferred?
            # (should it be connected to the when_connected
            # Deferreds?)
            d = self.connection_creator()
            d.addCallback(self._tor_connected)
            d.addErrback(self._tor_connection_failed)
# XXX 'should' be able to improve the error-handling by directly tying
# this Deferred into the notifications -- BUT we might try again, so
# we need to know "have we given up -- had an error" and only in that
# case send to the connected things. I think?
#            d.addCallback(self._maybe_notify_connected)

    def _timeout_expired(self):
        """
        A timeout was supplied during setup, and the time has run out.
        """
        self._did_timeout = True
        try:
            self.transport.signalProcess('TERM')
        except error.ProcessExitedAlready:
            # XXX why don't we just always do this?
            self.transport.loseConnection()

        fail = Failure(RuntimeError("timeout while launching Tor"))
        self._maybe_notify_connected(fail)

    def errReceived(self, data):
        """
        :api:`twisted.internet.protocol.ProcessProtocol <ProcessProtocol>` API
        """

        if self.stderr:
            self.stderr.write(data)

        if self.kill_on_stderr:
            self.transport.loseConnection()
            raise RuntimeError(
                "Received stderr output from slave Tor process: " + data)

    def cleanup(self):
        """
        Clean up my temporary files.
        """

        all([delete_file_or_tree(f) for f in self.to_delete])
        self.to_delete = []

    def processExited(self, reason):
        self._signal_on_exit(reason)

    def processEnded(self, status):
        """
        :api:`twisted.internet.protocol.ProcessProtocol <ProcessProtocol>` API
        """
        self.cleanup()

        if status.value.exitCode is None:
            if self._did_timeout:
                err = RuntimeError("Timeout waiting for Tor launch.")
            else:
                err = RuntimeError(
                    "Tor was killed (%s)." % status.value.signal)
        else:
            err = RuntimeError(
                "Tor exited with error-code %d" % status.value.exitCode)

        # hmmm, this log() should probably go away...not always an
        # error (e.g. .quit()
        log.err(err)
        self._maybe_notify_connected(Failure(err))

    def progress(self, percent, tag, summary):
        """
        Can be overridden or monkey-patched if you want to get
        progress updates yourself.
        """

        if self.progress_updates:
            self.progress_updates(percent, tag, summary)

    # the below are all callbacks

    def _tor_connection_failed(self, failure):
        # FIXME more robust error-handling please, like a timeout so
        # we don't just wait forever after 100% bootstrapped (that
        # is, we're ignoring these errors, but shouldn't do so after
        # we'll stop trying)
        # XXX also, should check if the failure is e.g. a syntax error
        # or an actually connection failure

        # okay, so this is a little trickier than I thought at first:
        # we *can* just relay this back to the
        # connection_creator()-returned Deferred, *but* we don't know
        # if this is "the last" error and we're going to try again
        # (and thus e.g. should fail all the when_connected()
        # Deferreds) or not.
        log.err(failure)
        self.attempted_connect = False
        return None

    def _status_client(self, arg):
        args = shlex.split(arg)
        if args[1] != 'BOOTSTRAP':
            return

        kw = find_keywords(args)
        prog = int(kw['PROGRESS'])
        tag = kw['TAG']
        summary = kw['SUMMARY']
        self.progress(prog, tag, summary)

        if prog == 100:
            if self._timeout_delayed_call:
                self._timeout_delayed_call.cancel()
                self._timeout_delayed_call = None
            self._maybe_notify_connected(self)

    @inlineCallbacks
    def _tor_connected(self, proto):
        txtorlog.msg("tor_connected %s" % proto)

        self.tor_protocol = proto
        self.tor_protocol.is_owned = self.transport.pid

        yield self.tor_protocol.post_bootstrap
        txtorlog.msg("Protocol is bootstrapped")
        yield self.tor_protocol.add_event_listener('STATUS_CLIENT', self._status_client)
        yield self.tor_protocol.queue_command('TAKEOWNERSHIP')
        yield self.tor_protocol.queue_command('RESETCONF __OwningControllerProcess')
        if self.config is not None and self.config.protocol is None:
            yield self.config.attach_protocol(proto)
        returnValue(self)  # XXX or "proto"?
