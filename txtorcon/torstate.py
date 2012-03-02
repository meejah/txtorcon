
from twisted.python import log, failure
from twisted.internet import defer
from twisted.internet.interfaces import IProtocolFactory, IReactorCore
from twisted.protocols.basic import LineOnlyReceiver
from zope.interface import implements, Interface

## outside this module, you can do "from txtorcon import Stream" etc.
from txtorcon.stream import Stream, IStreamListener, IStreamAttacher
from txtorcon.circuit import Circuit, ICircuitListener, ICircuitContainer
from txtorcon.router import Router, IRouterContainer
from txtorcon.addrmap import AddrMap
from txtorcon.torcontrolprotocol import ITorControlProtocol, parse_keywords

from spaghetti import FSM, State, Transition

import datetime
import warnings
import types
import os

DEBUG = False
USE_PSUTIL = False
## not really sure if this is a great way to make a module optional. I
## used this global instead of a try in the method guess_tor_pid so I
## may test both code-paths; see test_torstate
try:
    import psutil
    USE_PSUTIL = True
except ImportError:
    USE_PSUTIL = False

def build_state(proto):
    state = TorState(proto)
    return state.post_bootstrap

def wait_for_proto(proto):
    return proto.post_bootstrap

def build_tor_connection(endpoint, buildstate=True):
    """
    :Returns: a Deferred that fires with a TorControlProtocol or, if
    you specified buildstate=True, a TorState. In both cases, the
    object has finished bootstrapping
    (i.e. TorControlProtocol.post_bootstrap or TorState.post_bootstap
    has fired)
    """
    
    from txtorcon import TorProtocolFactory
    d = endpoint.connect(TorProtocolFactory())
    if buildstate:
        d.addCallback(build_state)
    else:
        d.addCallback(wait_for_proto)
    return d

class TorState(object):
    """
    This tracks the current state of Tor using a TorControlProtocol.

    On setup it first queries the initial state of streams and
    circuits. It then asks for updates via the listeners. It requires
    an ITorControlProtocol instance.

    You may add an IStreamAttacher to provide a custom mapping for
    Strams to Circuits (by default Tor chooses itself).

    This is also a good example of the various listeners, and acts as
    an ICircuitContainer and IRouterContainer.
    """
    
    implements (ICircuitListener, ICircuitContainer, IRouterContainer, IStreamListener)

    def __init__(self, protocol, bootstrap=True):
        self.protocol = ITorControlProtocol(protocol)
        
        ## could override these to get your own Circuit/Stream subclasses
        ## to track these things
        self.circuit_factory = Circuit
        self.stream_factory = Stream

        self.attacher = None
        """If set, provides :class:`txtorcon.IStreamAttacher` to attach new streams we hear about."""

        self.tor_binary = 'tor'

        self.circuit_listeners = []
        self.stream_listeners = []
        
        self.addrmap = AddrMap()
        self.circuits = {}              # keys on id (integer)
        self.streams = {}               # keys on id (integer)
        
        self.routers = {}               # keys by hexid (string) and by unique names
        self.routers_by_name = {}       # keys on name, value always list (many duplicate "Unnamed" routers, for example)
        self.guards = {}                # potentially-usable as entry guards, I think? (any router with 'Guard' flag)
        self.entry_guards = {}          # from GETINFO entry-guards, our current entry guards
        self.unusable_entry_guards = [] # list of entry guards we didn't parse out
        self.authorities = {}           # keys by name

        self.cleanup = None             # see set_attacher

        self.post_bootstrap = defer.Deferred()
        if bootstrap:
            if self.protocol.post_bootstrap:
                self.protocol.post_bootstrap.addCallback(self.bootstrap).addErrback(log.err)
            else:
                self.bootstrap()

    @defer.inlineCallbacks
    def bootstrap(self, arg=None):
        "This takes an arg so we can use it as a callback (see __init__)."

        ## update list of routers (must be before we do the circuit-status)
        ns = yield self.protocol.get_info_raw('ns/all')
        self.update_network_status(ns)

        ## update list of existing circuits
        cs = yield self.protocol.get_info_raw('circuit-status')
        self.circuit_status(cs)

        ## update list of streams
        ss = yield self.protocol.get_info_raw('stream-status')
        self.stream_status(ss)

        ## update list of existing address-maps
        key = 'address-mappings/all'
        am = yield self.protocol.get_info_raw(key)
        ## strip addressmappsings/all= and OK\n from raw data
        am = am[len(key)+1:]
        if am.strip() != 'OK':
            for line in am.split('\n')[:-1]:
                if len(line.strip()) == 0:
                    continue            # FIXME
                self.addrmap.update(line)

        ## FIXME can we use yield in here too? not really a huge deal
        ## that we don't wait for these right now...or does add_events
        ## then need to be inlineCallbacks decorated also?
        self.add_events()

        entries = yield self.protocol.get_info_raw("entry-guards")
        for line in entries.split('\n')[1:]:
            if len(line.strip()) == 0 or line.strip() == 'OK':
                continue
            args = line.split()
            (name, status) = args[:2]
            name = name[:41]

            ## this is sometimes redundant, as a missing entry guard
            ## usually means it won't be in our list of routers right
            ## now, but just being on the safe side
            if status.lower() != 'up':
                self.unusable_entry_guards.append(line)
                continue
                
            try:
                self.entry_guards[name] = self.router_from_id(name)
            except KeyError:
                self.unusable_entry_guards.append(line)

        ## who our Tor process is (process/pid is fairly new, so we
        ## guess at the Tor otherwise, by taking PID of the only
        ## available "tor" process, not guessing at all if there's 0
        ## or > 1 tor processes.
        pid = yield self.protocol.get_info_raw("process/pid").addErrback(self.guess_tor_pid)
        if pid:
            self.tor_pid = pid

        self.post_bootstrap.callback(self)
        self.post_boostrap = None

    def guess_tor_pid(self, *args):
        if self.protocol.is_owned:
            self.tor_pid = self.protocol.is_owned
        
        elif USE_PSUTIL:
            self.guess_tor_pid_psutil()
        
        else:
            self.guess_tor_pid_proc()
        return self.tor_pid

    def guess_tor_pid_psutil(self):
        procs = filter(lambda x: self.tor_binary in x.name, psutil.get_process_list())
        self.tor_pid = 0
        if len(procs) == 1:
            self.tor_pid = procs[0].pid
        return None

    def guess_tor_pid_proc(self):
        self.tor_pid = 0
        for pid in os.listdir('/proc'):
            if pid == 'self':
                continue
            p = os.path.join('/proc', pid, 'cmdline')
            if os.path.exists(p) and self.tor_binary in open(p, 'r').read():
                self.tor_pid = int(pid)
        return None
    

    def undo_attacher(self):
        """
        Shouldn't Tor handle this by turning this back to 0 if the
        controller that twiddled it disconnects?
        """
        
        return self.protocol.set_conf("__LeaveStreamsUnattached", 0)
    
    def set_attacher(self, attacher, myreactor):
        """
        Provide an IStreamAttacher to associate streams to
        circuits. This won't get turned on until after bootstrapping
        is completed. ("__LeaveStreamsUnattached" needs to be set to "1"
        and the existing circuits list needs to be populated).
        """

        react = IReactorCore(myreactor)
        if attacher:
            self.attacher = IStreamAttacher(attacher)
        else:
            self.attacher = None
        
        if self.attacher is None:
            self.undo_attacher()
            if self.cleanup:
                react.removeSystemEventTrigger(self.cleanup)
                self.cleanup = None
            
        else:
            self.protocol.set_conf("__LeaveStreamsUnattached", "1")
            self.cleanup = react.addSystemEventTrigger('before', 'shutdown',
                                                       self.undo_attacher)
        return None

    stream_close_reasons = {
        'REASON_MISC': 1,               # (catch-all for unlisted reasons)
        'REASON_RESOLVEFAILED': 2,      # (couldn't look up hostname)
        'REASON_CONNECTREFUSED': 3,     # (remote host refused connection) [*]
        'REASON_EXITPOLICY': 4,         # (OR refuses to connect to host or port)
        'REASON_DESTROY': 5,            # (Circuit is being destroyed)
        'REASON_DONE': 6,               # (Anonymized TCP connection was closed)
        'REASON_TIMEOUT': 7,            # (Connection timed out, or OR timed out while connecting)
        'REASON_NOROUTE': 8,            # (Routing error while attempting to contact destination)
        'REASON_HIBERNATING': 9,        # (OR is temporarily hibernating)
        'REASON_INTERNAL': 10,          # (Internal error at the OR)
        'REASON_RESOURCELIMIT': 11,     # (OR has no resources to fulfill request)
        'REASON_CONNRESET': 12,         # (Connection was unexpectedly reset)
        'REASON_TORPROTOCOL': 13,       # (Sent when closing connection because of Tor protocol violations.)
        'REASON_NOTDIRECTORY': 14,      # (Client sent RELAY_BEGIN_DIR to a non-directory relay.)
        }

    def close_stream(self, stream, reason='REASON_MISC'):
        if not self.streams.has_key(stream.id):
            raise KeyError("No such stream: %d" % stream.id)
            
        return self.protocol.queue_command("CLOSESTREAM %d %d" % (stream.id, self.stream_close_reasons[reason]))

    DO_NOT_ATTACH = object()
    def maybe_attach(self, stream):
        """
        If we've got a custom stream-attachment instance (see
        set_attacher) this will ask it for the appropriate
        circuit. Note that we ignore .exit URIs and let Tor deal with
        those (by passing circuit ID 0).

        The stream attacher is allowed to return a Deferred which will
        callback with the desired circuit.

        You may return the special object DO_NOT_ATTACH which will
        cause the circuit attacher to simply ignore the stream
        (neither attaching it, nor telling Tor to attach it).
        """
        
        if self.attacher:
            if stream.target_host is not None and '.exit' in stream.target_host:
                ## we want to totally ignore .exit URIs as these are
                ## used to specify a particular exit node, and trying
                ## to do STREAMATTACH on them will fail with an error
                ## from Tor anyway.
                if DEBUG: print "ignore attacher:",stream
                return

            circ = IStreamAttacher(self.attacher).attach_stream(stream, self.circuits)
            if circ is self.DO_NOT_ATTACH:
                return
            
            if circ == None:
                self.protocol.queue_command("ATTACHSTREAM %d 0" % stream.id)
                
            else:
                if isinstance(circ, defer.Deferred):
                    class IssueStreamAttach:
                        def __init__(self, state, streamid):
                            self.stream_id = streamid
                            self.state = state
                        def __call__(self, arg):
                            circid = arg.id
                            self.state.protocol.queue_command("ATTACHSTREAM %d %d" % (self.stream_id, circid))
                    circ.addCallback(IssueStreamAttach(self, stream.id)).addErrback(log.err)

                else:
                    if not self.circuits.has_key(circ.id):
                        raise Exception("Attacher returned a circuit unknown to me.")
                    if circ.state != 'BUILT':
                        raise Exception("Can only attach to BUILT circuits; %d is in %s." % (circ.id, circ.state))
                    self.protocol.queue_command("ATTACHSTREAM %d %d" % (stream.id, circ.id))

    def circuit_status(self, data):
        "Used internally as a callback for updating Circuit information"
        for line in data.split('\n')[1:-1]:
            self.circuit_update(line)

    def stream_status(self, data):
        "Used internally as a callback for updating Stream information"
        # there's a slight issue with a single-stream vs >= 2 streams,
        # in that in the latter case we have a line by itself with
        # "stream-status=" on it followed by the streams EXCEPT in the
        # single-stream case which has "stream-status=123 blahblah"
        # (i.e. the key + value on one line)

        lines = data.split('\n')[:-1]
        if len(lines) == 1:
            d = lines[0][len('stream-status='):]
            # if there are actually 0 streams, then there's nothing
            # left to parse
            if len(d):
                self.stream_update(d)
        else:
            [self.stream_update(line) for line in lines[1:]]

    def update_network_status(self, data):
        """
        Used internally as a callback for updating Router information
        from NS and NEWCONSENSUS events
        """
        last = None
        ##print "updatenetworkstatus",data[:80]
        lines = data.split('\n')[:-1]
        i = 0
        for line in lines:
            i += 1
            if line == 'ns/all=' or line[:5] == 'ns/id':
                continue
            args = line.split()
            if args[0] == 'r':
                last = Router(self.protocol)
                last.update(args[1],         # nickname
                            args[2],         # idhash
                            args[3],         # orhash
                            datetime.datetime.strptime(args[4]+args[5], '%Y-%m-%f%H:%M:%S'),
                            args[6],         # ip address
                            args[7],         # ORPort
                            args[8])         # DirPort
                
                if self.routers.has_key(last.id_hex):
                    last = self.routers[last.id_hex]
                    continue
                
                if self.routers_by_name.has_key(last.name):
                    self.routers_by_name[last.name].append(last)
                else:
                    self.routers_by_name[last.name] = [last]

                if self.routers.has_key(last.name):
                    self.routers[last.name] = None
                else:
                    self.routers[last.name] = last
                self.routers[last.id_hex] = last
                
            elif args[0] == 's':
                last.set_flags(args[1:])
                if 'guard' in last.flags:
                    self.guards[last.id_hex] = last
                if 'authority' in last.flags:
                    self.authorities[last.name] = last

            elif args[0] == 'w':
                last.set_bandwidth(int(args[1].split('=')[1]))
                
            else:                       # args[0] == 'p'
                last.set_policy(args[1:])
                last = None

        if DEBUG: print len(self.routers_by_name),"named routers found."
        ## remove any names we added that turned out to have dups
        for (k,v) in self.routers.items():
            if v is None:
                if DEBUG: print len(self.routers_by_name[k]),"dups:",k ##,self.routers_by_name[k]
                del self.routers[k]

        if DEBUG: print len(self.guards),"GUARDs"
                
    def newdesc_update(self, args):
        """
        Callback used internall for ORCONN and NEWDESC events to update Router information.
        
        FIXME: need to look at state for NEWDESC; if it's CLOSED we
        probably want to remove it from dicts...
        """

        hsh = args[:41]
        if not self.routers.has_key(hsh):
            if DEBUG: print "haven't seen",hsh,"yet!"
        self.protocol.get_info_raw('ns/id/%s' % hsh[1:]).addCallback(self.update_network_status).addErrback(log.err)
        if DEBUG: print "NEWDESC",args
                
    def circuit_update(self, line):
        "Used internally as a callback to update Circuit information from CIRC events."
        #print "circuit_update",line
        args = line.split()
        circ_id = int(args[0])
        
        if not self.circuits.has_key(circ_id):
            c = self.circuit_factory(self)
            c.listen(self)
            [c.listen(x) for x in self.circuit_listeners]
            c.update(args)

        else:
            self.circuits[circ_id].update(args)

    def stream_update(self, line):
        "Used internally as a callback to update Stream information from STREAM events."
        #print "stream_update",line
        if line.strip() == 'stream-status=':
            ## this happens if there are no active streams
            return
        
        args = line.split()
        assert len(args) >= 3

        stream_id = int(args[0])
        wasnew = False
        if not self.streams.has_key(stream_id):
            stream = self.stream_factory(self)
            self.streams[stream_id] = stream
            stream.listen(self)
            [stream.listen(x) for x in self.stream_listeners]
            wasnew = True
        self.streams[stream_id].update(args)
        
        ## if the update closed the stream, it won't be in our list
        ## anymore. FIXME: how can we ever hit such a case as the
        ## first update being a CLOSE?
        if wasnew and self.streams.has_key(stream_id):
            self.maybe_attach(self.streams[stream_id])

    def addr_map(self, addr):
        "Internal callback to update DNS cache. Listens to ADDRMAP."
        if DEBUG: print " --> addr_map",addr
        self.addrmap.update(addr)

    def add_circuit_listener(self, icircuitlistener):
        listen = ICircuitListener(icircuitlistener)
        for circ in self.circuits.values():
            circ.listen(listen)
        self.circuit_listeners.append(listen)

    def add_stream_listener(self, istreamlistener):
        listen = IStreamListener(istreamlistener)
        for stream in self.streams.values():
            stream.listen(listen)
        self.stream_listeners.append(listen)

    event_map = {
        #'GUARD': guard_update,
        'STREAM': stream_update,
        'CIRC': circuit_update,
        'NS': update_network_status,
        'NEWCONSENSUS': update_network_status,
        'ORCONN': newdesc_update,
        'NEWDESC': newdesc_update,
        'ADDRMAP': addr_map
#        'STATUS_GENERAL': status_general
        }
    @defer.inlineCallbacks
    def add_events(self):
        """
        Add listeners for all the events the controller is interested in.
        """

        for (event, func) in self.event_map.items():
            ## the map contains unbound methods, so we bind them
            ## to self so they call the right thing
            yield self.protocol.add_event_listener(event, types.MethodType(func, self, TorState))

    ## ICircuitContainer
        
    def find_circuit(self, circid):
        "ICircuitContainer API"
        return self.circuits[circid]

    ## IRouterContainer

    def router_from_id(self, routerid):
        "IRouterContainer API"
        return self.routers[routerid]

    ## implement IStreamListener
    
    def stream_new(self, stream):
        "IStreamListener: a new stream has been created"
        if DEBUG: print "stream_new",stream

    def stream_succeeded(self, stream):
        "IStreamListener: stream has succeeded"
        if DEBUG: print "stream_succeeded",stream

    def stream_attach(self, stream, circuit):
        """
        IStreamListener: the stream has been attached to a circuit. It
        seems you get an attach to None followed by an attach to real
        circuit fairly frequently. Perhaps related to __LeaveStreamsUnattached?
        """
        if DEBUG: print "stream_attach",stream.id,stream.target_host," -> ",circuit

    def stream_detach(self, stream, circuit):
        """
        IStreamListener
        """
        if DEBUG: print "stream_detach",stream.id

    def stream_closed(self, stream):
        "IStreamListener: stream has been closed (won't be in controller's list anymore)"
        if DEBUG: print "stream_closed",stream.id
        del self.streams[stream.id]

    def stream_failed(self, stream, reason, remote_reason):
        "IStreamListener: stream failed for some reason (won't be in controller's list anymore)"
        if DEBUG: print "stream_failed",stream.id
        del self.streams[stream.id]

    ## implement ICircuitListener

    def circuit_launched(self, circuit):
        "ICircuitListener API"
        if DEBUG: print "circuit_launched",circuit
        self.circuits[circuit.id] = circuit

    def circuit_extend(self, circuit, router):
        "ICircuitListener API"
        if DEBUG: print "circuit_extend:",circuit.id,router
    
    def circuit_built(self, circuit):
        "ICircuitListener API"
        if DEBUG: print "circuit_built:",circuit.id,'->'.join(map(lambda x: x.name+'.'+str(x.location.countrycode), circuit.path)), circuit.streams
    
    def circuit_new(self, circuit):
        "ICircuitListener API"
        if DEBUG: print "circuit_new:",circuit.id
        self.circuits[circuit.id] = circuit

    def circuit_destroy(self, circuit):
        "For circuit_closed and circuit_failed"
        if DEBUG: print "circuit_destroy:",circuit.id
        del self.circuits[circuit.id]

    def circuit_closed(self, circuit):
        "ICircuitListener API"
        if DEBUG: print "circuit_closed",circuit
        self.circuit_destroy(circuit)
        
    def circuit_failed(self, circuit, reason):
        "ICircuitListener API"
        if DEBUG: print "circuit_failed",circuit,reason
        self.circuit_destroy(circuit)
        
    ## explicitly build a circuit

    def build_circuit(self, routers):
        """
        Builds a circuit consisting of exactly the routers specified,
        in order.  This issues a series of EXTENDCIRCUIT calls to Tor;
        the deferred returned from this is for the final EXTEND. It
        will return the new circuit ID to you.
        """
        if routers[0] not in self.entry_guards.values():
            warnings.warn("Building a circuit not starting with a guard: %s" % (str(routers),), RuntimeWarning)
        return self.protocol.queue_command("EXTENDCIRCUIT 0 " + ','.join(map(lambda x: x.id_hex, routers)))
