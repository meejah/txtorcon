#!/usr/bin/env python

##
## This uses an IStreamListener and an ICircuitListener to log all
## built circuits and all streams that succeed.
##

import os
import sys
import stat
import random

from twisted.python import log
from twisted.internet import reactor, defer
from twisted.internet.endpoints import TCP4ClientEndpoint, UNIXClientEndpoint
from zope.interface import implements

try:
    import psutil
except ImportError:
    psutil = None
psutil = None

import txtorcon

def logCircuit(circuit):
    path = '->'.join(map(lambda x: x.location.countrycode, circuit.path))
    log.msg('Circuit %d (%s) is %s for purpose "%s"' % (circuit.id, path, circuit.state, circuit.purpose))

def logStream(stream, state):
    circ = ''
    if stream.circuit:
        circ = ' via circuit %d' % stream.circuit.id
    proc = txtorcon.util.process_from_address(stream.source_addr, stream.source_port, state)
    if proc:
        if psutil:
            proc = ' from process "%s"' % (' '.join(proc.cmdline), )
        else:
            proc = ' from process "%s"' % (proc,)
            
    elif stream.source_addr == '(Tor_internal)':
        proc = ' for Tor internal use'
        
    else:
        proc = ' from remote "%s:%s"' % (str(stream.source_addr), str(stream.source_port))
    log.msg('Stream %d to %s:%d attached%s%s' % (stream.id, stream.target_host, stream.target_port, circ, proc))
    
class StreamCircuitLogger(txtorcon.StreamListenerMixin, txtorcon.CircuitListenerMixin):

    def __init__(self, state):
        self.state = state
    
    def stream_attach(self, stream, circuit):
        logStream(stream, self.state)
    def stream_failed(self, stream, reason, remote_reason):
        print 'Stream %d failed because "%s"' % (stream.id, remote_reason)
    
    def circuit_built(self, circuit):
        logCircuit(circuit)
    def circuit_failed(self, circuit, reason):
        log.msg('circuit %d failed "%s"' % (circuit.id, reason))

def setup(state):
    log.msg('Connected to a Tor version %s' % state.protocol.version)

    listener = StreamCircuitLogger(state)
    state.add_circuit_listener(listener)
    state.add_stream_listener(listener)

    state.protocol.add_event_listener('STATUS_GENERAL', log.msg)
    state.protocol.add_event_listener('STATUS_SERVER', log.msg)
    state.protocol.add_event_listener('STATUS_CLIENT', log.msg)

    log.msg('Existing state when we connected:')
    for s in state.streams.values():
        logStream(s, state)

    log.msg('Existing circuits:')
    for c in state.circuits.values():
        logCircuit(c)

def setup_failed(arg):
    print "SETUP FAILED",arg
    log.err(arg)
    reactor.stop()

log.startLogging(sys.stdout)

if os.stat('/var/run/tor/control').st_mode & (stat.S_IRGRP | stat.S_IRUSR | stat.S_IROTH):
    print "using control socket"
    d = txtorcon.build_tor_connection(UNIXClientEndpoint(reactor, "/var/run/tor/control"))
    
else:
    d = txtorcon.build_tor_connection(TCP4ClientEndpoint(reactor, "localhost", 9051))
    
d.addCallback(setup).addErrback(setup_failed)
reactor.run()
