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

from twisted.internet import reactor, task
from twisted.internet.endpoints import TCP4ClientEndpoint
from zope.interface import implements

import txtorcon

class CircuitFailureWatcher(txtorcon.CircuitListenerMixin):

    total_circuits = 0
    failed_circuits = 0
    percent = 0.0

    def print_update(self):
        print self.information()

    def update_percent(self):
        self.percent = 100.0 * (float(self.failed_circuits) / float(self.total_circuits + self.failed_circuits))
        if self.percent > 50.0:
            print 'WARNING: %02.1f percent of all routes have failed: %d failed, %d built' % (self.percent, self.failed_circuits, self.total_circuits)

    def information(self):
        return '%02.1f%% of all circuits have failed: %d failed, %d built' % (self.percent, self.failed_circuits, self.total_circuits)

    def circuit_built(self, circuit):
        """ICircuitListener API"""
        self.total_circuits += 1
        self.update_percent()
        
    def circuit_failed(self, circuit, reason):
        """ICircuitListener API"""
        self.failed_circuits += 1
        self.update_percent()

def setup(state):
    print 'Connected to a Tor version %s' % state.protocol.version

    listener = CircuitFailureWatcher()
    listener.total_circuits = len(state.circuits)
    state.add_circuit_listener(listener)
    # print an update every minute
    task.LoopingCall(listener.print_update).start(60.0)

def setup_failed(arg):
    print "SETUP FAILED",arg
    print arg
    reactor.stop()

print "Connecting to localhost:9051 with AUTHCOOKIE authentication..."
d = txtorcon.build_tor_connection(TCP4ClientEndpoint(reactor, "localhost", 9051),
                                  build_state=True)
d.addCallback(setup).addErrback(setup_failed)
reactor.run()
