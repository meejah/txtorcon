"""
Contains an implementation of a L{Stream} abstraction used by
L{TorState} to represent all streams in Tor's state. There is also an
interface called L{IStreamListener} for listening for stream updates
(see also L{TorState.add_stream_listener}) and the interface called
L{IStreamAttacher} used by L{TorState} as a way to attach streams to
circuits"by hand"

"""

from twisted.python import log
from zope.interface import Interface
from circuit import ICircuitContainer
import ipaddr

class IStreamListener(Interface):
    """
    Notifications about changes to a L{Stream}.

    If you wish for your listener to be added to *all* new streams,
    see L{TorState.add_stream_listener}.
    """
    
    def stream_new(self, stream):
        "a new stream has been created"
    
    def stream_succeeded(self, stream):
        "stream has succeeded"
    
    def stream_attach(self, stream, circuit):
        "the stream has been attached to a circuit"

    def stream_detach(self, stream, reason):
        "the stream has been detached from its circuit"

    def stream_closed(self, stream):
        "stream has been closed (won't be in controller's list anymore)"

    def stream_failed(self, stream, reason, remote_reason):
        "stream failed for some reason (won't be in controller's list anymore)"

class IStreamAttacher(Interface):
    """
    Used by L{TorState} to map streams to circuits.

    Each time a new stream is created, this interface will be queried
    by L{TorState} to find out which circuit it should be attached to.
    """

    def attach_stream(self, stream, circuits):
        """
        @param stream: The stream to attach, which will be in NEW state.

        @param circuits: all currently available L{Circuit} objects in
        the L{TorState} in a dict indexed by id. Note they are not
        limited to BUILT circuits.

        You should return a Circuit instance which should be at state
        BUILT in the currently running Tor (you may get Circuits from
        an ICircuitContainer, which TorState implements). You may also
        return a Deferred which will callback with the desired
        circuit. In this case, you will probably need to be aware that
        the callback from TorState.build_circuit does NOT call back
        with a Circuit (just Tor's response of 'EXTEND 1234') and any
        circuit you do return must be in the BUILT state anyway (which
        the above will not). See examples/attach_streams_by_country.py
        for a complete example of using a Deferred in an
        IStreamAttacher.

        Alternatively, you may return None in which case the Tor
        controller will be told to choose a circuit itself.

        Note that Tor will refuse to attach to any circuit not in
        BUILT state; see ATTACHSTREAM in control-spec.txt

        Note also that you will not get a request to attach a stream
        that ends in .exit or .onion -- Tor won't let you specify how
        to attach .onion addresses anyway.
        """

class Stream(object):
    """
    Represents an active stream in Tor's state.

    @ivar circuit:
        Streams will generally be attached to circuits pretty
        quickly. If they are attached, circuit will be a L{Circuit}
        instance or None if this stream isn't yet attached to a
        circuit.

    @ivar state:
        Tor's idea of the stream's state, one of:
          - NEW: New request to connect
          - NEWRESOLVE: New request to resolve an address
          - REMAP: Address re-mapped to another
          - SENTCONNECT: Sent a connect cell along a circuit
          - SENTRESOLVE: Sent a resolve cell along a circuit
          - SUCCEEDED: Received a reply; stream established
          - FAILED: Stream failed and not retriable
          - CLOSED: Stream closed
          - DETACHED: Detached from circuit; still retriable

    @ivar target_host:
        Something like www.example.com -- the host the stream is destined for.

    @ivar target_port:
        The port the stream will exit to.

    @ivar target_addr:
        Target address, looked up (usually) by Tor (e.g. 127.0.0.1).

    @ivar id:
        The ID of this stream, a number (or None if unset).
    """

    def __init__(self, circuitcontainer):
        self.circuit_container = ICircuitContainer(circuitcontainer)

        self.id = None
        """An int, Tor's ID for this Circuit"""
        
        self.state = None
        """A string, Tor's idea of the state of this Circuit"""
        
        self.target_host = None
        """Usually a hostname, but sometimes an IP address (e.g. when we query existing state from Tor)"""
        
        self.target_addr = None
        """If available, the IP address we're connecting to (if None, see target_host instead)."""
        
        self.target_port = 0
        """The port we're connecting to."""
        
        self.circuit = None
        """If we've attached to a Circuit, this will be an instance of Circuit (otherwise None)."""
        
        self.listeners = []
        """A list of all connected ICircuitListeners"""
        
        self.source_addr = None
        """If available, the address from which this Stream originated (e.g. local process, etc). See get_process() also."""
        
        self.source_port = 0
        """If available, the port from which this Stream originated. See get_process() also."""

    def find_keywords(self, args):
        """FIXME: dup of the one in circuit, move somewhere shared"""
        kw = {}
        for x in args:
            if '=' in x:
                (k,v) = x.split('=',1)
                kw[k] = v
        return kw

    def listen(self, listen):
        """
        Attach an IStreamListener to this stream.

        See also L{TorState.add_stream_listener} to listen to all streams.

        @param listen: something that knows IStreamListener

        """
        
        listener = IStreamListener(listen)
        if listener not in self.listeners:
            self.listeners.append(listener)

    def unlisten(self, listener):
        self.listeners.remove(listener)

    def update(self, args):
        ##print "update",self.id,args

        if self.id is None:
            self.id = int(args[0])
        else:
            if self.id != int(args[0]):
                raise RuntimeError("Update for wrong stream.")

        kw = self.find_keywords(args)

        if kw.has_key('SOURCE_ADDR'):
            last_colon = kw['SOURCE_ADDR'].rfind(':')
            self.source_addr = kw['SOURCE_ADDR'][:last_colon]
            if self.source_addr != '(Tor_internal)':
                self.source_addr = ipaddr.IPAddress(self.source_addr)
            self.source_port = int(kw['SOURCE_ADDR'][last_colon+1:])

        self.state = args[1]
        if self.state in ['NEW', 'SUCCEEDED']:
            if self.target_host is None:
                last_colon = args[3].rfind(':')
                self.target_host = args[3][:last_colon]
                self.target_port = int(args[3][last_colon+1:])
                
            self.target_port = int(self.target_port)
            if self.state == 'NEW':
                if self.circuit != None:
                    log.err(RuntimeError("Weird: circuit valid in NEW"))
                [x.stream_new(self) for x in self.listeners]
            else:
                [x.stream_succeeded(self) for x in self.listeners]
            
        elif self.state == 'REMAP':
            self.target_addr = ipaddr.IPAddress(args[3][:args[3].rfind(':')])

        elif self.state == 'CLOSED':
            if self.circuit:
                self.circuit.streams.remove(self)
            self.circuit = None
            [x.stream_closed(self) for x in self.listeners]

        elif self.state == 'FAILED':
            reason = ''
            remote_reason = ''
            if kw.has_key('REMOTE_REASON'):
                remote_reason = kw['REMOTE_REASON']
            if kw.has_key('REASON'):
                reason = kw['REASON']
                
            if self.circuit:
                self.circuit.streams.remove(self)
            self.circuit = None
            [x.stream_failed(self, reason, remote_reason) for x in self.listeners]

        elif self.state == 'SENTCONNECT':
            pass#print 'SENTCONNECT',self,args

        elif self.state == 'DETACHED':
            reason = ''
            if len(args) >= 4 and args[4][:7] == 'REASON=':
                reason = args[4][7:]

            if self.circuit:
                self.circuit.streams.remove(self)
                self.circuit = None
                    
            [x.stream_detach(self, reason) for x in self.listeners]

        elif self.state == 'NEWRESOLVE':
            pass#print 'NEWRESOLVE',self,args

        elif self.state == 'SENTRESOLVE':
            pass#print 'SENTRESOLVE',self,args
            
        else:
            raise RuntimeError("Unknown state: %s" % self.state)

        ## see if we attached to a circuit. I believe this only
        ## happens on a SENTCONNECT or REMAP. DETACHED is excluded so
        ## we don't immediately re-add the circuit we just detached
        ## from
        if self.state not in ['CLOSED', 'FAILED', 'DETACHED']:
            cid = int(args[2])
            if cid == 0:
                if self.circuit and self in self.circuit.streams:
                    self.circuit.streams.remove(self)
                self.circuit = None

            else:
                if self.circuit is None:
                    self.circuit = self.circuit_container.find_circuit(cid)
                    if self not in self.circuit.streams:
                        self.circuit.streams.append(self)
                        [x.stream_attach(self, self.circuit) for x in self.listeners]
                else:
                    if self.circuit.id != cid:
                        log.err(RuntimeError('Circuit ID changed from %d to %d.' % (self.circuit.id, cid)))
            
        

    def __str__(self):
        c = ''
        if self.circuit:
            c = 'on %d ' % self.circuit.id
        return "<Stream %s %d %s%s -> %s port %d>" % (self.state, self.id, c, self.target_host, str(self.target_addr), self.target_port)


