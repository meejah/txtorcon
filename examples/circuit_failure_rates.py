#!/usr/bin/env python

##
## This uses an IStreamListener and an ICircuitListener to log all
## built circuits and all streams that succeed.
##

import os
import sys
import random

from twisted.python import log
from twisted.internet import reactor, defer
from twisted.internet.endpoints import TCP4ClientEndpoint
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

class CircuitFailureWatcher:
    implements(txtorcon.ICircuitListener)

    def __init__(self, total=0):
        self.total_circuits = total
        self.failed_circuits = 0

    def circuit_new(self, circuit):
        pass
    def circuit_launched(self, circuit):
        pass
    def circuit_extend(self, circuit, router):
        pass
    def circuit_built(self, circuit):
        self.total_circuits += 1
        logCircuit(circuit)
    def circuit_closed(self, circuit):
        pass
    def circuit_failed(self, circuit, reason):
        log.msg('Circuit failed: %d for purpose "%s" because "%s"' % (circuit.id, circuit.purpose, reason))
        self.failed_circuits += 1
        percent = 100.0 * (float(self.failed_circuits) / float(self.total_circuits + self.failed_circuits))
        log.msg('%02.1f%% of all circuits have failed; %d of %d' % (percent, self.failed_circuits, self.total_circuits))
        if percent > 50.0:
            log.warn('More than half (%02.1f%%) of all circuits have failed since I started monitoring' % percent);

def setup(state):
    log.msg('Connected to a Tor version %s' % state.protocol.version)

    listener = CircuitFailureWatcher(len(state.circuits))
    state.add_circuit_listener(listener)

    state.protocol.add_event_listener('STATUS_GENERAL', log.msg)
    state.protocol.add_event_listener('STATUS_SERVER', log.msg)
    state.protocol.add_event_listener('STATUS_CLIENT', log.msg)

    log.msg('Existing circuits when we connected:')
    for c in state.circuits.values():
        logCircuit(c)

def setup_failed(arg):
    print "SETUP FAILED",arg
    log.err(arg)
    reactor.stop()

log.startLogging(sys.stdout)
d = txtorcon.build_tor_connection(TCP4ClientEndpoint(reactor, "localhost", 9051))
d.addCallback(setup).addErrback(setup_failed)
reactor.run()
