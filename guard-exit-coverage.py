#!/usr/bin/env python

##
## Determine if all exits can be reached from everything marked as a
## guard.
## 

import os
import sys
import random

from twisted.internet import reactor, task
from twisted.internet.endpoints import TCP4ClientEndpoint
from zope.interface import implements

import txtorcon

DEBUG = False

def uniquify(seq):
    """From http://www.peterbe.com/plog/uniqifiers-benchmark, not order preserving"""
    set = {}
    map(set.__setitem__, seq, [])
    return set.keys()

class CircuitProber(object):
    implements(txtorcon.ICircuitListener)

    def __init__(self, tor_state):
        """tor_state (a TorState instance) must be bootstrapped already"""
        
        self.state = tor_state
        self.max_circuit_build_requests = 10
        self.outstanding_circuit_ids = {}
        self.circuit_build_requests = 0
        self.guards = filter(lambda x: 'guard' in x.flags, self.state.unique_routers)
        ##self.guards = uniquify(self.state.entry_guards.values())
        self.exits = filter(lambda x: 'exit' in x.flags, self.state.unique_routers)
        self.circuits = []
        self._create_possible_circuits()

        self.succeeded = []
        self.failed = []

        print "I have %d guards and %d exits, or %d permutations to test" % (len(self.guards), len(self.exits), len(self.circuits))
        print len(self.guards), len(uniquify(self.guards))
        print len(self.exits), len(uniquify(self.exits))
        self._maybe_launch_circuits()

    def _create_possible_circuits(self):
        ##middles = filter(lambda x: 'fast' in x.flags, self.state.routers.values())
        for g in self.guards:
            for e in self.exits:
                if g != e:
                    ##self.circuits.append((g, random.choice(middles), e))
                    self.circuits.append((g, e))
        print "created %d circuit combinations",len(self.circuits)
        self.circuits = self.circuits[:20]

    ## ICircuitListener API
    def circuit_new(self, circuit):
        pass
    def circuit_launched(self, circuit):
        pass
    def circuit_extend(self, circuit, router):
        pass
    
    def circuit_built(self, circuit):
        try:
            self.succeeded.append((circuit.id, self.outstanding_circuit_ids[circuit.id]))
            del self.outstanding_circuit_ids[circuit.id]
            self.circuit_build_requests -= 1
            
        except KeyError:
            # this will happen for the circuits Tor built by itself.
            print "wasn't waiting for circuit:",circuit
        self._maybe_launch_circuits()
        
    def circuit_closed(self, circuit):
        pass
    
    def circuit_failed(self, circuit, reason):
        print "FAILED:",circuit,reason
        try:
            self.failed.append((reason, self.outstanding_circuit_ids[circuit.id]))
            del self.outstanding_circuit_ids[circuit.id]
            self.circuit_build_requests -= 1
            
        except KeyError:
            print "wasn't waiting for circuit:",circuit
        self._maybe_launch_circuits()

    def _circuit_completed(self, arg, circ):
        if DEBUG: print "COMPLETE",arg,circ
        self.outstanding_circuit_ids[int(arg.split()[1])] = circ

    def _circuit_failed(self, arg, circ):
        print "Even our request to build a circuit was rejected"
        print circ,arg.getErrorMessage()
        self.circuit_build_requests -= 1
        if DEBUG: print "FAILED",arg,circ
        self.failed.append((arg.getErrorMessage(), circ))

    def _output_results(self):
        print "%d successful, %d failed" % (len(self.succeeded), len(self.failed))

        print self.succeeded
        print self.failed

        def write_csv(fname, thelist):
            f = open(fname, 'w')
            f.write('guard_hash, exit_hash, guard_name, exit_name, note\n')
            for (arg, circ) in thelist:
                f.write('%s, %s, %s, %s, "%s"\n' % (circ[0].id_hex, circ[0].name, circ[1].id_hex, circ[1].name, arg))
            f.close()

        write_csv('succeeded.csv', self.succeeded)
        write_csv('failed.csv', self.failed)

    def _maybe_launch_circuits(self):
        if len(self.circuits) == 0 and self.circuit_build_requests == 0:
            print "All done"
            self._output_results()
            reactor.stop()
            return
            
        while self.circuit_build_requests < self.max_circuit_build_requests and len(self.circuits) > 0:
            self.circuit_build_requests += 1            
            circ = self.circuits[0]
            self.circuits = self.circuits[1:]
            d = self.state.build_circuit(circ)
            d.addCallback(self._circuit_completed, circ)
            d.addErrback(self._circuit_failed, circ)

def setup(processprotocol):
    proto = processprotocol.tor_protocol
    state = txtorcon.TorState(proto)
    state.post_bootstrap.addCallback(really_setup).addErrback(setup_failed)

def really_setup(state):
    print 'Connected to a Tor version %s' % state.protocol.version
    probe = CircuitProber(state)
    state.add_circuit_listener(probe)

def setup_failed(arg):
    print "SETUP FAILED",arg
    print arg
    reactor.stop()

def update(percent, tag, summary):
    print "  %d%% %s" % (int(percent), summary)

print "Launching new Tor instance:"
config = txtorcon.TorConfig()
d = txtorcon.launch_tor(config, reactor, progress_updates=update)
d.addCallback(setup).addErrback(setup_failed)
reactor.run()
