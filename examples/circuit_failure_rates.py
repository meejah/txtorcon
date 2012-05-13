#!/usr/bin/env python

##
## This example uses ICircuitListener to monitor how many circuits have
## failed since the monitor started up. If this figure is more than 50%,
## a warning-level message is logged.
## 
## Like the :ref:`stream_circuit_logger.py` example, we also log all new
## circuits.
## 

import os
import sys
import random
import signal

from twisted.internet import reactor, task
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.python import usage
from zope.interface import implements

import txtorcon

class Options(usage.Options):
    """
    command-line options we understand
    """
    
    optParameters = [
        ['failed', 'f', 0, 'Starting value for number of failed circuits.'],
        ['built', 'b', 0, 'Starting value for the total number of built cicuits.']
        ]

class CircuitFailureWatcher(txtorcon.CircuitListenerMixin):

    built_circuits = 0
    failed_circuits = 0
    percent = 0.0
    failed_circuit_ids = []
    per_guard_built = {}
    per_guard_failed = {}

    def print_update(self):
        print self.information()

    def update_percent(self):
        self.percent = 100.0 * (float(self.failed_circuits) / float(self.built_circuits + self.failed_circuits))
        if self.percent > 50.0:
            print 'WARNING: %02.1f percent of all routes have failed: %d failed, %d built' % (self.percent, self.failed_circuits, self.built_circuits)

    def information(self):
        rtn = '%02.1f%% of all circuits have failed: %d failed, %d built' % (self.percent, self.failed_circuits, self.built_circuits)
        for g in self.per_guard_built.keys():
            per_guard_percent = 100.0*(self.per_guard_failed[g]/(self.per_guard_built[g]+self.per_guard_failed[g]))
            rtn = rtn + '\n  %s: %d built, %d failed: %02.1f%%' % (g, self.per_guard_built[g], self.per_guard_failed[g],
                                                                   per_guard_percent)
        return rtn

    def circuit_built(self, circuit):
        """ICircuitListener API"""
        if circuit.purpose == 'GENERAL':
            if len(circuit.path) > 0 and circuit.path[0] not in self.state.entry_guards.values():
                print "WEIRD: first circuit hop not in entry guards:",circuit,circuit.path
                return
            
            self.built_circuits += 1
            self.update_percent()

            if len(circuit.path) != 3 and len(circuit.path) != 4:
                print "WEIRD: circuit has odd pathlength:",circuit,circuit.path
            try:
                self.per_guard_built[circuit.path[0].unique_name] += 1
            except KeyError:
                self.per_guard_built[circuit.path[0].unique_name] = 1.0
                self.per_guard_failed[circuit.path[0].unique_name] = 0.0
        
    def circuit_failed(self, circuit, reason):
        """ICircuitListener API"""
        if circuit.purpose == 'GENERAL':
            if len(circuit.path) > 0 and circuit.path[0] not in self.state.entry_guards.values():
                print "WEIRD: first circuit hop not in entry guards:",circuit,circuit.path
                return
            
            self.failed_circuits += 1
            print "failed",circuit.id
            if not circuit.id in self.failed_circuit_ids:
                self.failed_circuit_ids.append(circuit.id)
            else:
                print "WARNING: duplicate message for",circuit

            if len(circuit.path) > 0:
                try:
                    self.per_guard_failed[circuit.path[0].unique_name] += 1
                except KeyError:
                    self.per_guard_failed[circuit.path[0].unique_name] = 1.0
                    self.per_guard_built[circuit.path[0].unique_name] = 0.0
                
            self.update_percent()

listener = CircuitFailureWatcher()
def setup(state):
    print 'Connected to a Tor version %s' % state.protocol.version
    global options, listener

    if options['failed']:
        listener.failed_circuits = int(options['failed'])
    if options['built']:
        listener.built_circuits = int(options['built'])
    listener.state = state              # FIXME use ctor (ditto for options, probably)
    
    for circ in filter(lambda x: x.purpose == 'GENERAL', state.circuits.values()):
        if circ.state == 'BUILT':
            listener.circuit_built(circ)
    state.add_circuit_listener(listener)
    # print an update every minute
    task.LoopingCall(listener.print_update).start(60.0)

def setup_failed(arg):
    print "SETUP FAILED",arg
    print arg
    reactor.stop()

options = Options()
options.parseOptions(sys.argv[1:])

def on_shutdown(*args):
    global listener
    print 'To carry on where you left off, run:'
    print '  %s --failed %d --built %d' % (sys.argv[0], listener.failed_circuits, listener.built_circuits)
reactor.addSystemEventTrigger('before', 'shutdown', on_shutdown)

print "Connecting to localhost:9051 with AUTHCOOKIE authentication..."
d = txtorcon.build_tor_connection(TCP4ClientEndpoint(reactor, "localhost", 9051),
                                  build_state=True)
d.addCallback(setup).addErrback(setup_failed)
reactor.run()
