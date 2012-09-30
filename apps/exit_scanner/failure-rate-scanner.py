#!/usr/bin/env python

##
## This picks N random guards, and lets Tor use its own selection
## algorithms to set up circuits. Then, failure rates are counted.
##
## TODO:
##  . maybe better to just use circuit_failure_rate.py to count up the
##    statistics (and improve its statistics-handling to be moar-bettar)
##
##  . we don't do any proper time handling, nor set up multiple
##    circuits at once
##
##  . can we do something better when Tor says "can't do it" (i.e. 551
##    respose to the EXTEND 0)?
##
##  . are the NOPATH failures things we should count as failures? I
##    doubt it since it seems it's not even contacting the first hop.
##
##  . actually use the options
##
##  . the $ on (or not on) the beginning of node IDs is really
##    annoying. Can I do anything about that? Can I just always use
##    it?
##
## NOTES:
##
##  . can run examples/monitor.py to get Tor output while running.
##  . can run circuit_failure_rates.py as well, I suppose.
##

import os
import sys
import math

from twisted.internet import reactor, task
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.python import usage
from zope.interface import implements

import txtorcon

class Options(usage.Options):

    optParameters = [
        ['guards', 'G', 10, 'Total number of Guards to choose.', int],
        ['circuits', 'c', 100, 'Total number of circuits to set up (distributed evenly over Guards).', int],
        ['connect', 'c', "localhost:9051", 'Tor control socket to connect to in host:port format, like "localhost:9051" (the default).'],
        ['rate', 'r', 10, 'Number of circuits to set up per minute.', int],
        ]

    def __init__(self):
        usage.Options.__init__(self)

class GuardStatistics:
    id_hex = ''
    failure = 0
    success = 0

class CircuitCreator(txtorcon.CircuitListenerMixin):

    def __init__(self, reactor, tor_protocol, guards, total_circuits):
        """
        :param tor_protocol:
            (a TorControlProtocol instance) must be bootstrapped
            already

        :param guards:
            list of Guard node IDs to use

        :param total_circuits:
            total number of circuits to ask Tor to create
        """

        """reactor to use; useful if we want to write tests"""
        self.reactor = reactor

        """TorState instance, should be bootstrapped already"""
        self.protocol = tor_protocol

        """A list of all the Router instances we will use as Guards (must actually have the Guard flag or Tor will probabyl reject them)"""
        self.guards = guards

        """Total number of circuits we'll create"""
        self.total_circuits = total_circuits

        """per-guard statistics"""
        self.statistics = {}

        self.circuits_per_guard = math.ceil(float(self.total_circuits) / float(len(guards)))
        if self.circuits_per_guard < 1:
            raise RuntimeError("Not enough circuits (%d) for even one per guard (%d)." % (self.total_circuits, len(guards)))
        
        self.current_guard = None
        self.current_guard_circuits = 0
        self.last_circuit_extend = 0
        self._try_next_guard()

    def _error(self, f):
        print "ERROR",f
        return f

    def _try_next_guard(self):
        """
        Set up Tor to use the next guard in the list, and reset our
        circuit count.
        """

        if len(self.guards) == 0:
            print "no more guards, we're done?"
            print "statistics:"
            for (hexid, stats) in self.statistics.items():
                print " ",hexid
                rate = float(stats.failure) / float(stats.success + stats.failure)
                print "    built:",stats.success,"failed:",stats.failure,"failure rate:",(rate*100.0),"%"
            reactor.stop()
            return

        self.current_guard = self.guards[0]
        self.current_guard_circuits = 0
        self.guards = self.guards[1:]
        gs = GuardStatistics()
        gs.id_hex = self.current_guard
        self.statistics[self.current_guard] = gs
        
        print "setting up to use guard:",self.current_guard
        d = self.protocol.set_conf("StrictNodes", 1, "EntryNodes", str(self.current_guard))
        d.addCallback(self._setup_circuit).addErrback(self._error)
        return d

    def _setup_circuit(self, arg):
        print "_setup_circuit():",arg
        # tell Tor to build a new circuit, and we don't care about the
        # path. Since we've set only one guard, though, and
        # strictguardnodes we should get a random (albeit
        # tor-selected) route using that guard.

        timediff = self.reactor.seconds() - self.last_circuit_extend
        if timediff < 2.0:
            print "waiting",(2.0 - timediff),"seconds"
            self.reactor.callLater(2.0 - timediff, self._setup_circuit, arg)
            return None
        
        self.last_circuit_extend = self.reactor.seconds()
        d = self.protocol.queue_command("EXTENDCIRCUIT 0 purpose=controller")
        d.addErrback(self._setup_circuit)
        return None

    def _increment_circuit_count(self):
        print "INCrement"
        # we successfully set up a circuit. if we've set up enough for
        # this guard already, go to the next guard. if not, construct
        # another for this guard.

        self.current_guard_circuits += 1
        print "We've tried",self.current_guard_circuits,"for guard",self.current_guard
        if self.current_guard_circuits >= self.circuits_per_guard:
            print "rotating guard"
            return self._try_next_guard()

    ## ICircuitListener API (only implementing the ones we want,
    ## thanks to CircuitListenerMixin)

    def circuit_built(self, circuit):
        print "BUILT",circuit
        if len(circuit.path) and circuit.path[0].id_hex[1:] == self.current_guard:
            print "DINGDINGDING!"
            self.statistics[self.current_guard].success += 1
            self._increment_circuit_count()

    def circuit_closed(self, circuit):
        pass

    def circuit_failed(self, circuit, reason):
        print "FAILED:",circuit,reason
        if len(circuit.path) and circuit.path[0].id_hex[1:] == self.current_guard:
            print "Oh Noes!"
            self.statistics[self.current_guard].failure += 1
            self._increment_circuit_count()


def setup(processprotocol):
    proto = processprotocol.tor_protocol
    state = txtorcon.TorState(proto)
    state.post_bootstrap.addCallback(really_setup).addErrback(setup_failed)

def really_setup(state):
    print 'Connected to a Tor version %s' % state.protocol.version
    creator = CircuitCreator(reactor, state.protocol, ['11A0239FC6668705F68842811318B669C636F86E', 'D5EDC74F2FB81E6AC1A8EBA56448F71DDFAA4AE5'], 10)
    state.add_circuit_listener(creator)

def setup_failed(arg):
    print "SETUP FAILED",arg
    print arg
    reactor.stop()

def update(percent, tag, summary):
    print "  %d%% %s" % (int(percent), summary)

if False:
    print "Launching new Tor instance:"
    config = txtorcon.TorConfig()
    config.SOCKSPort = 9999
    config.ControlPort = 1234
    d = txtorcon.launch_tor(config, reactor, progress_updates=update)
    d.addCallback(setup).addErrback(setup_failed)

else:
    d = txtorcon.build_tor_connection(TCP4ClientEndpoint(reactor, "localhost", 9051))
    d.addCallback(really_setup).addErrback(setup_failed)

reactor.run()
