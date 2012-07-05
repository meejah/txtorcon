"""
Contains an implementation of a :class:`Stream abstraction used by
:class:`TorState to represent all streams in Tor's state. There is
also an interface called :class:`interface.IStreamListener` for
listening for stream updates (see also
:meth:`TorState.add_stream_listener`) and the interface called
:class:interface.IStreamAttacher` used by :class:`TorState` as a way
to attach streams to circuits "by hand"

"""

from twisted.python import log
from txtorcon.interface import ICircuitContainer, IStreamListener
import ipaddr

from txtorcon.util import find_keywords


def maybe_ip_addr(addr):
    """
    Tries to return an IPAddress, otherwise returns a string. I could
    explicitly check for .exit or .onion at the end instead.
    """

    try:
        return ipaddr.IPAddress(addr)
    except ValueError:
        return str(addr)


class Stream(object):
    """
    Represents an active stream in Tor's state (:class:`txtorcon.TorState`).

    :ivar circuit:
        Streams will generally be attached to circuits pretty
        quickly. If they are attached, circuit will be a
        :class:`txtorcon.Circuit` instance or None if this stream
        isn't yet attached to a circuit.

    :ivar state:
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

    :ivar target_host:
        Something like www.example.com -- the host the stream is destined for.

    :ivar target_port:
        The port the stream will exit to.

    :ivar target_addr:
        Target address, looked up (usually) by Tor (e.g. 127.0.0.1).

    :ivar id:
        The ID of this stream, a number (or None if unset).
    """

    def __init__(self, circuitcontainer):
        """
        :param circuitcontainer: an object which implements
        :class:`interface.ICircuitContainer`
        """

        self.circuit_container = ICircuitContainer(circuitcontainer)

        ## FIXME: Sphinx doesn't seem to understand these variable
        ## docstrings, so consolidate with above if Sphinx is the
        ## answer -- actually it does, so long as the :ivar: things
        ## are never mentioned it seems.

        self.id = None
        """An int, Tor's ID for this :class:`txtorcon.Circuit`"""

        self.state = None
        """A string, Tor's idea of the state of this
        :class:`txtorcon.Stream`"""

        self.target_host = None
        """Usually a hostname, but sometimes an IP address (e.g. when
        we query existing state from Tor)"""

        self.target_addr = None
        """If available, the IP address we're connecting to (if None,
        see target_host instead)."""

        self.target_port = 0
        """The port we're connecting to."""

        self.circuit = None
        """If we've attached to a :class:`txtorcon.Circuit`, this will
        be an instance of :class:`txtorcon.Circuit` (otherwise None)."""

        self.listeners = []
        """A list of all connected
        :class:`txtorcon.interface.ICircuitListener` instances."""

        self.source_addr = None
        """If available, the address from which this Stream originated
        (e.g. local process, etc). See get_process() also."""

        self.source_port = 0
        """If available, the port from which this Stream
        originated. See get_process() also."""

    def listen(self, listen):
        """
        Attach an :class:`txtorcon.interface.IStreamListener` to this stream.

        See also :meth:`txtorcon.TorState.add_stream_listener` to
        listen to all streams.

        :param listen: something that knows
        :class:`txtorcon.interface.IStreamListener`
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

        kw = find_keywords(args)

        if 'SOURCE_ADDR' in kw:
            last_colon = kw['SOURCE_ADDR'].rfind(':')
            self.source_addr = kw['SOURCE_ADDR'][:last_colon]
            if self.source_addr != '(Tor_internal)':
                self.source_addr = maybe_ip_addr(self.source_addr)
            self.source_port = int(kw['SOURCE_ADDR'][last_colon + 1:])

        self.state = args[1]
        if self.state in ['NEW', 'SUCCEEDED']:
            if self.target_host is None:
                last_colon = args[3].rfind(':')
                self.target_host = args[3][:last_colon]
                self.target_port = int(args[3][last_colon + 1:])

            self.target_port = int(self.target_port)
            if self.state == 'NEW':
                if self.circuit is not None:
                    log.err(RuntimeError("Weird: circuit valid in NEW"))
                [x.stream_new(self) for x in self.listeners]
            else:
                [x.stream_succeeded(self) for x in self.listeners]

        elif self.state == 'REMAP':
            self.target_addr = maybe_ip_addr(args[3][:args[3].rfind(':')])

        elif self.state == 'CLOSED':
            if self.circuit:
                self.circuit.streams.remove(self)
            self.circuit = None
            [x.stream_closed(self) for x in self.listeners]

        elif self.state == 'FAILED':
            reason = ''
            remote_reason = ''
            if 'REMOTE_REASON' in kw:
                remote_reason = kw['REMOTE_REASON']
            if 'REASON' in kw:
                reason = kw['REASON']

            if self.circuit:
                self.circuit.streams.remove(self)
            self.circuit = None
            [x.stream_failed(self, reason, remote_reason) for x in self.listeners]

        elif self.state == 'SENTCONNECT':
            pass  #print 'SENTCONNECT',self,args

        elif self.state == 'DETACHED':
            reason = ''
            if len(args) >= 4 and args[4][:7] == 'REASON=':
                reason = args[4][7:]

            if self.circuit:
                self.circuit.streams.remove(self)
                self.circuit = None

            [x.stream_detach(self, reason) for x in self.listeners]

        elif self.state == 'NEWRESOLVE':
            pass  #print 'NEWRESOLVE',self,args

        elif self.state == 'SENTRESOLVE':
            pass  #print 'SENTRESOLVE',self,args

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
        return "<Stream %s %d %s%s -> %s port %d>" % (self.state,
                                                      self.id,
                                                      c,
                                                      self.target_host,
                                                      str(self.target_addr),
                                                      self.target_port)
