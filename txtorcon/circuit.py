# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import with_statement

import time
import datetime
import random

from twisted.python.failure import Failure
from twisted.python import log
from twisted.internet import defer
from twisted.internet.interfaces import IReactorTime, IStreamClientEndpoint
from zope.interface import Interface, implementer  # XXX FIXME

from .interface import IRouterContainer, IStreamAttacher
from txtorcon.util import find_keywords, maybe_ip_addr
from txtorcon import web


# look like "2014-01-25T02:12:14.593772"
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S'


@implementer(IStreamClientEndpoint)
@implementer(IStreamAttacher)
class TorCircuitEndpoint(object):
    def __init__(self, reactor, torstate, circuit, target_endpoint, got_source_port,
                 socks_config=None):
        self._reactor = reactor
        self._state = torstate
        self._target_endpoint = target_endpoint
        self._circuit = circuit
        self._attached = defer.Deferred()
        self._got_source_port = got_source_port
        self._socks_config = socks_config

    def attach_stream_failure(self, stream, fail):
        print("failed:", fail)
        return None

    @defer.inlineCallbacks
    def attach_stream(self, stream, circuits):
        real_addr = yield self._got_source_port
        # joy oh joy, ipaddress wants unicode, Twisted gives us bytes...
        real_host = maybe_ip_addr(unicode(real_addr.host))

        # Note: matching via source port/addr is way better than
        # target because multiple streams may be headed at the same
        # target ... but a bit of a pain to pass it all through to here :/
        if stream.source_addr == real_host and \
           stream.source_port == real_addr.port:

            # XXX note to self: we'll want to listen for "circuit_failed"
            # etc. on just this one circuit, so that we can .errback()
            # attached if the circuit fails before we get to do
            # this-here...
            # XXX could check target_host, target_port to be sure...?
            self._attached.callback(None)
            defer.returnValue(self._circuit)

    @defer.inlineCallbacks
    def connect(self, protocol_factory):
        """IStreamClientEndpoint API"""
        # need to:
        # 1. add 'our' attacher to state
        # 2. do the "underlying" connect
        # 3. recognize our stream
        # 4. attach it to our circuit
        yield self._state.add_attacher(self, self._reactor)
        try:
            proto = yield self._target_endpoint.connect(protocol_factory)
            yield self._attached  # ensure this fired, too
            defer.returnValue(proto)

        finally:
            yield self._state.remove_attacher(self, self._reactor)


class Circuit(object):
    """
    Used by :class:`txtorcon.TorState` to represent one of Tor's circuits.

    This is kept up-to-date by the :class`txtorcon.TorState` that owns it, and
    individual circuits can be listened to for updates (or listen to
    every one using :meth:`txtorcon.TorState.add_circuit_listener`)

    :ivar path:
        contains a list of :class:`txtorcon.Router` objects
        representing the path this Circuit takes. Mostly this will be
        3 or 4 routers long. Note that internally Tor uses single-hop
        paths for some things. See also the *purpose*
        instance-variable.

    :ivar streams:
        contains a list of Stream objects representing all streams
        currently attached to this circuit.

    :ivar state:
        contains a string from Tor describing the current state of the
        stream. From control-spec.txt section 4.1.2, these are:
            - NEW: New request to connect
            - NEWRESOLVE: New request to resolve an address
            - REMAP: Address re-mapped to another
            - SENTCONNECT: Sent a connect cell along a circuit
            - SENTRESOLVE: Sent a resolve cell along a circuit
            - SUCCEEDED: Received a reply; stream established
            - FAILED: Stream failed and not retriable
            - CLOSED: Stream closed
            - DETACHED: Detached from circuit; still retriable

    :ivar purpose:
        The reason this circuit was built. Values can currently be one
        of (but see control-spec.txt 4.1.1):
          - GENERAL
          - HS_CLIENT_INTRO
          - HS_CLIENT_REND
          - HS_SERVICE_INTRO
          - HS_SERVICE_REND
          - TESTING
          - CONTROLLER

    For most purposes, you'll want to look at GENERAL circuits only.


    :ivar id:
        The ID of this circuit, a number (or None if unset).
    """

    def __init__(self, routercontainer):
        """
        :param routercontainer: should implement
        :class:`txtorcon.interface.IRouterContainer`.
        """
        self.listeners = []
        self.router_container = IRouterContainer(routercontainer)
        self._torstate = routercontainer  # XXX FIXME
        self.path = []
        self.streams = []
        self.purpose = None
        self.id = None
        self.state = 'UNKNOWN'
        self.build_flags = []
        self.flags = {}

        # this is used to hold a Deferred that will callback() when
        # this circuit is being CLOSED or FAILED.
        self._closing_deferred = None

        # caches parsed value for time_created()
        self._time_created = None

        # all notifications for when_built
        self._when_built = []

    # XXX backwards-compat for old .is_built for now
    @property
    def is_built(self):
        return self.when_built()

    def when_built(self):
        """
        Returns a Deferred that is callback()'d (with this Circuit
        instance) when this circuit hits BUILT.

        If it's already BUILT when this is called, you get an
        already-successful Deferred; otherwise, the state must change
        to BUILT.
        """
        d = defer.Deferred()
        if self.state == 'BUILT':
            d.callback(self)
        else:
            self._when_built.append(d)
        return d

    def web_agent(self, reactor, socks_endpoint, pool=None):
        """
        :param socks_endpoint: create one with
            :meth:`txtorcon.TorState.socks_endpoint`. Can be a Deferred.

        :param pool: passed on to the Agent (as ``pool=``)
        """
        return web.tor_agent(
            reactor,
            socks_endpoint,
            circuit=self,
            pool=pool,
        )

    # XXX should make this API match above web_agent (i.e. pass a
    # socks_endpoint) or change the above...
    def stream_via(self, reactor, host, port,
                   socks_endpoint,
                   use_tls=False):
        """
        This returns an IStreamClientEndpoint that wraps the passed-in
        endpoint such that it goes via Tor, and via this parciular
        circuit.

        We match the streams up using their source-ports, so even if
        there are many streams in-flight to the same destination they
        will align correctly. For example, to cause a stream to go to
        ``torproject.org:443`` via a particular circuit::

            from twisted.internet.endpoints import HostnameEndpoint

            dest = HostnameEndpoint(reactor, "torproject.org", 443)
            circ = yield torstate.build_circuit()  # lets Tor decide the path
            tor_ep = circ.stream_via(dest)
            # 'factory' is for your protocol
            proto = yield tor_ep.connect(factory)

        Note that if you're doing client-side Web requests, you
        probably want to use `treq
        <http://treq.readthedocs.org/en/latest/>`_ or ``Agent``
        directly so call :meth:`txtorcon.Circuit.web_agent` instead.

        :param socks_endpoint: should be a Deferred firing a valid
            IStreamClientEndpoint pointing at a Tor SOCKS port (or an
            IStreamClientEndpoint already).
        """
        from .endpoints import TorClientEndpoint
        got_source_port = defer.Deferred()
        ep = TorClientEndpoint(
            reactor, host, port,
            socks_endpoint,
            tls=use_tls,
            got_source_port=got_source_port,
        )
        return TorCircuitEndpoint(reactor, self._torstate, self, ep, got_source_port)

    @property
    def time_created(self):
        if self._time_created is not None:
            return self._time_created
        if 'TIME_CREATED' in self.flags:
            # strip off milliseconds
            t = self.flags['TIME_CREATED'].split('.')[0]
            tstruct = time.strptime(t, TIME_FORMAT)
            self._time_created = datetime.datetime(*tstruct[:7])
        return self._time_created

    def listen(self, listener):
        if listener not in self.listeners:
            self.listeners.append(listener)

    def unlisten(self, listener):
        self.listeners.remove(listener)

    def close(self, **kw):
        """
        This asks Tor to close the underlying circuit object. See
        :meth:`txtorcon.torstate.TorState.close_circuit`
        for details.

        You may pass keyword arguments to take care of any Flags Tor
        accepts for the CLOSECIRCUIT command. Currently, this is only
        "IfUnused". So for example: circ.close(IfUnused=True)

        :return: Deferred which callbacks with this Circuit instance
        ONLY after Tor has confirmed it is gone (not simply that the
        CLOSECIRCUIT command has been queued). This could be a while
        if you included IfUnused.
        """

        self._closing_deferred = defer.Deferred()

        def close_command_is_queued(*args):
            return self._closing_deferred
        d = self._torstate.close_circuit(self.id, **kw)
        d.addCallback(close_command_is_queued)
        return self._closing_deferred

    def age(self, now=datetime.datetime.utcnow()):
        """
        Returns an integer which is the difference in seconds from
        'now' to when this circuit was created.

        Returns None if there is no created-time.
        """
        if not self.time_created:
            return None
        return (now - self.time_created).seconds

    def _create_flags(self, kw):
        """
        this clones the kw dict, adding a lower-case version of every
        key (duplicated in stream.py; put in util?)
        """

        flags = {}
        for k in kw.keys():
            flags[k] = kw[k]
            flags[k.lower()] = kw[k]
        return flags

    def update(self, args):
        # print "Circuit.update:",args
        if self.id is None:
            self.id = int(args[0])
            for x in self.listeners:
                x.circuit_new(self)

        else:
            if int(args[0]) != self.id:
                raise RuntimeError("Update for wrong circuit.")
        self.state = args[1]

        kw = find_keywords(args)
        self.flags = kw
        if 'PURPOSE' in kw:
            self.purpose = kw['PURPOSE']
        if 'BUILD_FLAGS' in kw:
            self.build_flags = kw['BUILD_FLAGS'].split(',')

        if self.state == 'LAUNCHED':
            self.path = []
            for x in self.listeners:
                x.circuit_launched(self)
        else:
            if self.state != 'FAILED' and self.state != 'CLOSED':
                if len(args) > 2:
                    self.update_path(args[2].split(','))

        if self.state == 'BUILT':
            for x in self.listeners:
                x.circuit_built(self)
            for d in self._when_built:
                d.callback(self)
            self._when_built = []

        elif self.state == 'CLOSED':
            if len(self.streams) > 0:
                # FIXME it seems this can/does happen if a remote
                # router crashes or otherwise shuts down a circuit
                # with streams on it still
                log.err(RuntimeError("Circuit is %s but still has %d streams" %
                                     (self.state, len(self.streams))))
            flags = self._create_flags(kw)
            self.maybe_call_closing_deferred()
            for x in self.listeners:
                x.circuit_closed(self, **flags)

        elif self.state == 'FAILED':
            if len(self.streams) > 0:
                log.err(RuntimeError("Circuit is %s but still has %d streams" %
                                     (self.state, len(self.streams))))
            flags = self._create_flags(kw)
            self.maybe_call_closing_deferred()
            for x in self.listeners:
                x.circuit_failed(self, **flags)

    def maybe_call_closing_deferred(self):
        """
        Used internally to callback on the _closing_deferred if it
        exists.
        """

        if self._closing_deferred:
            self._closing_deferred.callback(self)
            self._closing_deferred = None

    def update_path(self, path):
        """
        There are EXTENDED messages which don't include any routers at
        all, and any of the EXTENDED messages may have some arbitrary
        flags in them. So far, they're all upper-case and none start
        with $ luckily. The routers in the path should all be
        LongName-style router names (this depends on them starting
        with $).

        For further complication, it's possible to extend a circuit to
        a router which isn't in the consensus. nickm via #tor thought
        this might happen in the case of hidden services choosing a
        rendevouz point not in the current consensus.
        """

        oldpath = self.path
        self.path = []
        for p in path:
            if p[0] != '$':
                break

            # this will create a Router if we give it a router
            # LongName that doesn't yet exist
            router = self.router_container.router_from_id(p)

            self.path.append(router)
            if len(self.path) > len(oldpath):
                for x in self.listeners:
                    x.circuit_extend(self, router)
                oldpath = self.path

    def __str__(self):
        path = ' '.join([x.ip for x in self.path])
        return "<Circuit %d %s [%s] for %s>" % (self.id, self.state, path,
                                                self.purpose)


class ICircuitBuilder(Interface):
    def create(timeout=None):
        """
        Returns a Deferred that fires with a new Circuit instance. Will
        never fail (we just keep trying more circuits), unless timeout
        is specified, in which case this will fail if we don't build a
        circuit before that time.
        """


def circuit_builder_fixed_exit(reactor, torstate, exit_node):
    """
    Returns a Deferred that fires with an object that implements
    ICircuitBuilder, whose circuits are always using the specified
    node as the exit node.
    """

    def select_exit(torstate):
        return exit_node
    return CircuitBuilder(reactor, torstate, select_exit=select_exit)


def circuit_builder_fixed_country(reactor, torstate, country_code):
    """
    Returns a Deferred that fires with an object that implements
    ICircuitBuilder, whose circuits are always using the specified
    node as the exit node.
    """

    @defer.inlineCallbacks
    def select_exit(torstate):
        while True:
            r = random.choice(torstate.all_routers)
            loc = yield r.get_location()
            if loc.country_code == country_code:
                defer.returnValue(r)
                return
    return CircuitBuilder(reactor, torstate, select_exit=select_exit)


@implementer(ICircuitBuilder)
class CircuitBuilder(object):
    """
    (XXX prototyping!)
    This object knows how to build circuits given some configuration.
    """

    # XXX maybe we want like "fixed_exit_circuit_builder(state, exit)"
    # or "fixed_country_circuit_builder(state, exit_country)" (see
    # above) etc. instead of trying to make some kind of configuration
    # stuff work ...
    @classmethod
    @defer.inlineCallbacks
    def from_config(cls, torstate, config):
        """
        Create a new CircuitBuilder instance from the given
        :class:`txtorcon.TorState` intance and some configuration. The
        configuration is a dictionary, with the following keys:

          -
        """
        yield torstate.post_bootstrap
        raise NotImplemented(__name__)

    def __init__(self, reactor, torstate,
                 select_guard=None,
                 select_middle=None,
                 select_exit=None):
        """
        It is intended that you call one of the ICircuitBuilder factory
        methods to instantiate these objects.

        all the select_*() functions can be async
        """
        self._state = torstate
        self._reactor = IReactorTime(reactor)
        self._select_guard = select_guard if select_guard else self._default_select_guard
        self._select_middle = select_middle if select_middle else self._default_select_middle
        self._select_exit = select_exit if select_exit else self._default_select_exit

    @staticmethod
    def _default_select_guard(torstate):
        # XXX really random? or always try the first one?
        return random.choice(
            torstate.entry_guards.values()
        )

    @staticmethod
    def _default_select_middle(torstate):
        # XXX FIXME use Tor's selection algorithm (i.e. weighted by
        # consensus weight etc.)
        return random.choice(
            torstate.all_routers
        )

    @staticmethod
    def _default_select_exit(torstate):
        # XXX FIXME use Tor's selection algorithm (i.e. weighted by
        # consensus weight etc.)
        return random.choice(
            filter(
                lambda relay: 'exit' in relay.flags,
                torstate.all_routers
            )
        )

    @defer.inlineCallbacks
    def _select_path(self):
        """
        internal helper. selects a new circuit path based on the
        configuration rules.
        """
        guard = yield self._select_guard(self)
        middle = yield self._select_middle(self)
        exit_ = yield self._select_exit(self)
        defer.returnValue([guard, middle, exit_])

    @defer.inlineCallbacks
    def create(self, timeout=None):
        """
        This returns a Deferred that fires when another circuit is created
        according to the rules in the configuration. This will never
        fail, unless a timeout is supplied -- if one circuit fails, we
        just try another one.
        """
        now = None if timeout is None else self._reactor.seconds()
        while True:
            path = yield self._select_path()
            try:
                # XXX should be a DeferredList with a deferLater() in
                # it along with the circuit-build, but only-if we've
                # got a timeout
                print("Creating circuit: {}".format([x.id_hex for x in path]))
                circ = yield self._state.build_circuit(routers=path)
            except Exception:
                # log warning?
                if timeout is not None:
                    diff = self._reactor.seconds() - now
                    if diff > timeout:
                        raise RuntimeError(
                            "Failed to build a circuit after {}s.".format(
                                diff
                            )
                        )
                continue
            defer.returnValue(circ)
            return


class CircuitBuildTimedOutError(Exception):
        """
    This exception is thrown when using `timed_circuit_build`
    and the circuit build times-out.
    """


def build_timeout_circuit(tor_state, reactor, path, timeout, using_guards=False):
    """
    returns a deferred which fires when the
    circuit build succeeds or fails to build.
    CircuitBuildTimedOutError will be raised unless we
    receive a circuit build result within the `timeout` duration.
    """
    d = tor_state.build_circuit(path, using_guards)
    reactor.callLater(timeout, d.cancel)

    def trap_cancel(f):
        f.trap(defer.CancelledError)
        return Failure(CircuitBuildTimedOutError("circuit build timed out"))
    d.addCallback(lambda circuit: circuit.when_built())
    d.addErrback(trap_cancel)
    return d
