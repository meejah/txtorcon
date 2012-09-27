#!/usr/bin/env python

##
## Determine if all exits can be reached from everything marked as a
## guard.
##

import os
import sys
import random
import bisect

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

def weighted_choice(routers):
    """
    Returns a function that makes a weighted random choice from
    routers, based on bandwidth.
    http://stackoverflow.com/a/526300/84322
    """

    added_weights = []
    last_sum = 0

    for router in routers:
        last_sum += router.bandwidth
        added_weights.append(last_sum)

    def choice(rnd=random.random, bis=bisect.bisect):
        return routers[bis(added_weights, rnd() * last_sum)]
    return choice

class CircuitProber(object):
    implements(txtorcon.ICircuitListener)

    def __init__(self, reactor, tor_state):
        """tor_state (a TorState instance) must be bootstrapped already"""

        """reactor to use; useful if we want to write tests"""
        self.reactor = reactor

        """TorState instance, should be bootstrapped already"""
        self.state = tor_state

        """Maximum number of outstanding circuit build requests (FIXME does Tor have a limit? What's reasonable?)"""
        self.max_circuit_build_requests = 10

        """Circuits we're waiting for currently; key is circuit_id"""
        self.outstanding_circuit_ids = {}

        """Total number of build requests we've issued"""
        self.circuit_build_requests = 0

        """All the nodes taggged 'Guard'"""
        self.guards = filter(lambda x: 'guard' in x.flags, self.state.unique_routers)

        """All the nodes tagged 'Exit'"""
        self.exits = filter(lambda x: 'exit' in x.flags, self.state.unique_routers)

        """Any router we might use as a middle node"""
        self.middles = filter(lambda x: 'fast' in x.flags, self.state.routers.values())

        """All the circuits that we want to test; these are 3-tuples of Router instances."""
        self.circuits = []

        """The circuits that succeeded."""
        self.succeeded = []

        """The circuits that failed."""
        self.failed = []

        """Circuits for which the request to build was rejected; we retry a few times with different middles"""
        self.rejected = {}

        """All the circuits we will test."""
        self.circuits = self._create_possible_circuits()

        print "I have %d guards and %d exits (that's %d combinations)" % (len(self.guards), len(self.exits), len(self.guards)*len(self.exits))
        print "We will test %d circuits." % len(self.circuits)

        self._maybe_launch_circuits()

    def _create_possible_circuits(self):
        """
        Create the circuits to test. Here we iterate every guard, and
        for each guard produce 5 random circuits consisting of a
        random exit (weighted by bandwidth) and a random middle node
        (also weighted by bandwidth, from the set of all routers
        tagged Fast).
        """

        weighted_exit_chooser = weighted_choice(self.exits)
        weighted_middle_chooser = weighted_choice(self.middles)

        circs = []
        for g in self.guards:
            for _ in range(5):          # 5 exits per entry
                e = weighted_exit_chooser()
                while e == g:
                    e = weighted_exit_chooser()
                    ## some guards are also exits

                circs.append((g, weighted_middle_chooser(), e))

        return circs

    def print_update(self):
        print "%d succeeded, %d failed, %d still to test" % (len(self.succeeded), len(self.failed), len(self.circuits))

    ## ICircuitListener API
    def circuit_new(self, circuit):
        pass
    def circuit_launched(self, circuit):
        pass
    def circuit_extend(self, circuit, router):
        pass

    def circuit_built(self, circuit):
        try:
            circ, started = self.outstanding_circuit_ids[circuit.id]
            diff = self.reactor.seconds() - started
            self.succeeded.append((circuit.id, circ, diff))
            del self.outstanding_circuit_ids[circuit.id]
            self.circuit_build_requests -= 1

        except KeyError:
            # this will happen for the circuits Tor built by itself.
            pass#print "wasn't waiting for circuit:",circuit
        self._maybe_launch_circuits()

    def circuit_closed(self, circuit):
        pass

    def circuit_failed(self, circuit, reason):
        #print "FAILED:",circuit,reason
        try:
            circ, started = self.outstanding_circuit_ids[circuit.id]
            diff = self.reactor.seconds() - started
            self.failed.append((reason, circ, diff))
            del self.outstanding_circuit_ids[circuit.id]
            self.circuit_build_requests -= 1

        except KeyError:
            pass#print "wasn't waiting for circuit:",circuit
        self._maybe_launch_circuits()

    def _circuit_build_issued(self, arg, circ):
        """
        Callback when our request to build a circuit succeeded.
        """

        if DEBUG: print "COMPLETE",arg,circ
        self.outstanding_circuit_ids[int(arg.split()[1])] = (circ, self.reactor.seconds())

    def _circuit_build_failed(self, arg, circ):
        """
        callback in case our build request was rejected.
        """

        try:
            self.rejected[circ[0]] += 1
        except KeyError:
            self.rejected[circ[0]] = 1

        try:
            self.rejected[circ[2]] += 1
        except KeyError:
            self.rejected[circ[2]] = 1

        print "Even our request to build a circuit was rejected:",arg.getErrorMessage()
        print circ,arg.getErrorMessage()
        self.circuit_build_requests -= 1

        if self.rejected[circ[0]] < 5 and self.rejected[circ[2]] < 5:
            print "...trying again, with a different middle"
            circ = (circ[0], random.choice(self.middles), circ[2])
            self.circuits.append(circ)

        return

    def _output_results(self):
        """
        Dump out our results.
        """

        print "Couldn't successfully ask Tor to build with these:"
        print self.rejected
        print

        print "%d successful, %d failed" % (len(self.succeeded), len(self.failed))

        def write_csv(fname, thelist):
            f = open(fname, 'w')
            f.write('guard_hash, exit_hash, guard_name, exit_name, time, note\n')
            for (arg, circ, diff) in thelist:
                f.write('%s, %s, %s, %s, %f, "%s"\n' % (circ[0].id_hex, circ[0].name, circ[2].id_hex, circ[2].name, diff, arg))
            f.close()

        write_csv('succeeded.csv', self.succeeded)
        write_csv('failed.csv', self.failed)

    def _maybe_launch_circuits(self):
        """
        This tries to launch some more circuit build requests. If
        we're already at our cap, it does nothing. If there are no
        more circuits to build and all outstanding ones have failed or
        succeeded, we exit.

        FIXME: change how we exit; this method should only be for new
        requests.
        """

        if len(self.circuits) == 0 and self.circuit_build_requests == 0:
            print "All done"
            self._output_results()
            reactor.stop()
            return

        while self.circuit_build_requests < self.max_circuit_build_requests and len(self.circuits) > 0:
            self.circuit_build_requests += 1
            circ = self.circuits[0]
            self.circuits = self.circuits[1:]
            ##print "requesting:",circ
            d = self.state.build_circuit(circ)
            d.addCallback(self._circuit_build_issued, circ)
            d.addErrback(self._circuit_build_failed, circ)

def setup(processprotocol):
    proto = processprotocol.tor_protocol
    state = txtorcon.TorState(proto)
    state.post_bootstrap.addCallback(really_setup).addErrback(setup_failed)

def really_setup(state):
    print 'Connected to a Tor version %s' % state.protocol.version
    probe = CircuitProber(reactor, state)
    state.add_circuit_listener(probe)
    task.LoopingCall(probe.print_update).start(60.0)

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
