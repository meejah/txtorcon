# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import with_statement

import time
from datetime import datetime

from twisted.python.failure import Failure
from twisted.python import log
from twisted.internet import defer

from .interface import IRouterContainer
from txtorcon.util import find_keywords


# look like "2014-01-25T02:12:14.593772"
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S'


# note to self: TorCircuitEndpoint can be merged only after deciding
# the attacher API


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
        stream. From control-spec.txt section 4.1.1, these are:
           - LAUNCHED: circuit ID assigned to new circuit
           - BUILT: all hops finished, can now accept streams
           - EXTENDED: one more hop has been completed
           - FAILED: circuit closed (was not built)
           - CLOSED: circuit closed (was built)

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
        # XXX ^ should probably be when_closed() etc etc...

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

        If the circuit will never hit BUILT (e.g. it is abandoned by
        Tor before it gets to BUILT) you will receive an errback
        """
        # XXX note to self: we never do an errback; fix this behavior
        d = defer.Deferred()
        if self.state == 'BUILT':
            d.callback(self)
        else:
            self._when_built.append(d)
        return d

    # note to self: web_agent and stream_via should be merged after
    # working out the set_attacher etc interface.

    @property
    def time_created(self):
        if self._time_created is not None:
            return self._time_created
        if 'TIME_CREATED' in self.flags:
            # strip off milliseconds
            t = self.flags['TIME_CREATED'].split('.')[0]
            tstruct = time.strptime(t, TIME_FORMAT)
            self._time_created = datetime(*tstruct[:7])
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

        # we're already closed; nothing to do
        if self.state == 'CLOSED':
            return defer.succeed(None)

        # someone already called close() but we're not closed yet
        if self._closing_deferred:
            d = defer.Deferred()

            def closed(arg):
                d.callback(arg)
                return arg
            self._closing_deferred.addBoth(closed)
            return d

        # actually-close the circuit
        self._closing_deferred = defer.Deferred()

        def close_command_is_queued(*args):
            return self._closing_deferred
        d = self._torstate.close_circuit(self.id, **kw)
        d.addCallback(close_command_is_queued)
        return self._closing_deferred

    def age(self, now=None):
        """
        Returns an integer which is the difference in seconds from
        'now' to when this circuit was created.

        Returns None if there is no created-time.
        """
        if not self.time_created:
            return None
        if now is None:
            now = datetime.utcnow()
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
            self._notify_when_built()

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

    # XXX should use the util helper
    def _notify_when_built(self, err=None):
        for d in self._when_built:
            if err is None:
                d.callback(self)
            else:
                d.errback(Failure(err))
        self._when_built = []

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


class CircuitBuildTimedOutError(Exception):
        """
    This exception is thrown when using `timed_circuit_build`
    and the circuit build times-out.
    """


def build_timeout_circuit(tor_state, reactor, path, timeout, using_guards=False):
    """
    Build a new circuit within a timeout.

    CircuitBuildTimedOutError will be raised unless we receive a
    circuit build result (success or failure) within the `timeout`
    duration.

    :returns: a Deferred which fires when the circuit build succeeds (or
        fails to build).
    """
    timed_circuit = []
    d = tor_state.build_circuit(routers=path, using_guards=using_guards)

    def get_circuit(c):
        timed_circuit.append(c)
        return c

    def trap_cancel(f):
        f.trap(defer.CancelledError)
        if timed_circuit:
            d2 = timed_circuit[0].close()
        else:
            d2 = defer.succeed(None)
        d2.addCallback(lambda ign: Failure(CircuitBuildTimedOutError("circuit build timed out")))
        return d2

    d.addCallback(get_circuit)
    d.addCallback(lambda circ: circ.when_built())
    d.addErrback(trap_cancel)
    reactor.callLater(timeout, d.cancel)
    return d
