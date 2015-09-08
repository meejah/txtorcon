# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import with_statement

import time
import datetime

from twisted.python import log
from twisted.internet import defer
from .interface import IRouterContainer

from txtorcon.util import find_keywords

# look like "2014-01-25T02:12:14.593772"
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S'


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

    :ivar is_built:
        A Deferred that will callback() when this Circuit hits BUILT state.
    """

    def __init__(self, routercontainer):
        """
        :param routercontainer: should implement
        :class:`txtorcon.interface.IRouterContainer`.
        """
        self.listeners = []
        self.router_container = IRouterContainer(routercontainer)
        self.torstate = routercontainer
        self.path = []
        self.streams = []
        self.purpose = None
        self.id = None
        self.state = 'UNKNOWN'
        self.build_flags = []
        self.flags = {}

        #: callback()d when this circuit hits BUILT
        self.is_built = defer.Deferred()

        # this is used to hold a Deferred that will callback() when
        # this circuit is being CLOSED or FAILED.
        self._closing_deferred = None

        # caches parsed value for time_created()
        self._time_created = None

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
        d = self.torstate.close_circuit(self.id, **kw)
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
            [x.circuit_new(self) for x in self.listeners]

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
            [x.circuit_launched(self) for x in self.listeners]
        else:
            if self.state != 'FAILED' and self.state != 'CLOSED':
                if len(args) > 2:
                    self.update_path(args[2].split(','))

        if self.state == 'BUILT':
            [x.circuit_built(self) for x in self.listeners]
            if not self.is_built.called:
                self.is_built.callback(self)

        elif self.state == 'CLOSED':
            if len(self.streams) > 0:
                # FIXME it seems this can/does happen if a remote
                # router crashes or otherwise shuts down a circuit
                # with streams on it still
                log.err(RuntimeError("Circuit is %s but still has %d streams" %
                                     (self.state, len(self.streams))))
            flags = self._create_flags(kw)
            self.maybe_call_closing_deferred()
            [x.circuit_closed(self, **flags) for x in self.listeners]

        elif self.state == 'FAILED':
            if len(self.streams) > 0:
                log.err(RuntimeError("Circuit is %s but still has %d streams" %
                                     (self.state, len(self.streams))))
            flags = self._create_flags(kw)
            self.maybe_call_closing_deferred()
            [x.circuit_failed(self, **flags) for x in self.listeners]

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
                [x.circuit_extend(self, router) for x in self.listeners]
                oldpath = self.path

    def __str__(self):
        path = ' '.join([x.ip for x in self.path])
        return "<Circuit %d %s [%s] for %s>" % (self.id, self.state, path,
                                                self.purpose)
