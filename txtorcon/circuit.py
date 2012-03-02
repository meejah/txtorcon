import sys

from twisted.python import log
from zope.interface import Interface
from router import IRouterContainer

class ICircuitContainer(Interface):
    """
    An interface that contains a bunch of Circuit objects and can look
    them up by id.
    """
    
    def find_circuit(self, id):
        "return a circuit for the id, or exception."

class ICircuitListener(Interface):
    """
    An interface to listen for updates to Circuits.
    """
    
    def circuit_new(self, circuit):
        """A new circuit has been created.  You'll always get one of
        these for every Circuit even if it doesn't go through the "launched"
        state."""
        
    def circuit_launched(self, circuit):
        "A new circuit has been started."

    def circuit_extend(self, circuit, router):
        "A circuit has been extended to include a new router hop."

    def circuit_built(self, circuit):
        "A circuit has been extended to all hops (usually 3 for user circuits)."

    def circuit_closed(self, circuit):
        "A circuit has been closed cleanly (won't be in controller's list any more)."
        
    def circuit_failed(self, circuit, reason):
        """A circuit has been closed because something went wrong.

        The circuit won't be in the TorState's list anymore. The
        reason comes from Tor (see tor-spec.txt). It is one of the
        following strings: MISC, RESOLVEFAILED, CONNECTREFUSED,
        EXITPOLICY, DESTROY, DONE, TIMEOUT, NOROUTE, HIBERNATING,
        INTERNAL,RESOURCELIMIT, CONNRESET, TORPROTOCOL, NOTDIRECTORY,
        END, PRIVATE_ADDR.

        However, don't depend on that: it could be anything.        
        """

class Circuit(object):
    """
    Used by TorState to represent one of Tor's circuits.

    This is kept up-to-date by the L{TorState} that owns it, and
    individual circuits can be listened to for updates (or listen to
    every one using L{TorState.add_circuit_listener})

    @ivar path:
        contains a list of Router objects representing the path this
        Circuit takes. Mostly this will be 3 or 4 routers long. Note
        that internally Tor uses single-hop paths for some things. See
        also the L{purpose} instance-variable.

    @ivar streams:
        contains a list of Stream objects representing all streams
        currently attached to this circuit.

    @ivar state:
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

    @ivar purpose:
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

    @ivar id:
        The ID of this circuit, a number (or None if unset).
    """

    def __init__(self, routercontainer):
        "routercontainer should implement IRouterContainer"
        self.listeners = []
        self.router_container = IRouterContainer(routercontainer)
        self.path = []
        self.streams = []
        self.purpose = None
        self.id = None
        self.state = 'UNKNOWN'
        
    def find_keywords(self, args):
        """FIXME: dup of the one in stream, move somewhere shared"""
        kw = {}
        for x in args:
            if '=' in x:
                (k,v) = x.split('=',1)
                kw[k] = v
        return kw

    def listen(self, listener):
        if listener not in self.listeners:
            self.listeners.append(listener)

    def unlisten(self, listener):
        self.listeners.remove(listener)
                    
    def update(self, args):
        ##print "Circuit.update:",args
        if self.id is None:
            self.id = int(args[0])
            [x.circuit_new(self) for x in self.listeners]
        else:
            if int(args[0]) != self.id:
                raise RuntimeError("Update for wrong circuit.")
        self.state = args[1]

        kw = self.find_keywords(args)
        if kw.has_key('PURPOSE'):
            self.purpose = kw['PURPOSE']
            
        if self.state == 'LAUNCHED':
            self.path = []
            [x.circuit_launched(self) for x in self.listeners]
        else:
            if self.state != 'FAILED' and self.state != 'CLOSED':
                self.update_path(args[2].split(','))

        if self.state == 'BUILT':
            [x.circuit_built(self) for x in self.listeners]

        elif self.state == 'CLOSED':
            if len(self.streams) > 0:
                log.err(RuntimeError("Circuit is %s but still has %d streams" % (self.state, len(self.streams))))
            [x.circuit_closed(self) for x in self.listeners]

        elif self.state == 'FAILED':
            if len(self.streams) > 0:
                log.err(RuntimeError("Circuit is %s but still has %d streams" % (self.state, len(self.streams))))
            reason = 'unknown'
            if kw.has_key('REASON'):
                reason = kw['REASON']
            [x.circuit_failed(self, reason) for x in self.listeners]

    def update_path(self, path):
        oldpath = self.path
        self.path = []
        for router in path:
            p = router[:41]
            router = self.router_container.router_from_id(p)
            self.path.append(router)
            if len(self.path) > len(oldpath):
                [x.circuit_extend(self, router) for x in self.listeners]
                oldpath = self.path
        
    def __str__(self):
        #return "<Circuit %d %s [%s]>" % (self.id, self.state, ' '.join(map(lambda x: x.name, self.path)))
        return "<Circuit %d %s [%s] for %s>" % (self.id, self.state, ' '.join(map(lambda x: x.ip, self.path)), self.purpose)
