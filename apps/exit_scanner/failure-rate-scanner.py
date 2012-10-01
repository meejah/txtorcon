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
from twisted.python import usage, failure
from zope.interface import implements

import txtorcon

class Options(usage.Options):

    optParameters = [
        ['guards', 'G', 10, 'Total number of Guards to choose.', int],
        ['circuits', 'C', 100, 'Total number of circuits to set up (distributed evenly over Guards).', int],
        ['address', 'a', "localhost:9051", 'Tor control socket to connect to in host:port format, like "localhost:9051" (the default).'],
        ['max-outstanding', 'x', 10, "Maximum number of circuits we'll ask Tor to build at one time."]
        ]

    def __init__(self):
        usage.Options.__init__(self)

class GuardStatistics:
    id_hex = ''
    failure = 0
    success = 0
    errors = 0
    nopath = 0

class CircuitCreator(txtorcon.CircuitListenerMixin):

    def __init__(self, reactor, tor_protocol, guards, total_circuits, max_outstanding):
        """
        :param tor_protocol:
            (a TorControlProtocol instance) must be bootstrapped
            already

        :param guards:
            list of Guard node IDs to use

        :param total_circuits:
            total number of circuits to ask Tor to create

        :param max_outstanding:
            the number of circuits we'll ask Tor to build at once
            (i.e. until we get a failed or built status for a circuit,
            it's outstanding)
        """

        """reactor to use; useful if we want to write tests"""
        self.reactor = reactor

        """TorProtocol instance, should be bootstrapped already"""
        self.protocol = tor_protocol

        """A list of all the Router instances we will use as Guards (must actually have the Guard flag or Tor will probabyl reject them). This list contains just the hex IDs as strings."""
        self.guards = guards

        """Total number of circuits we'll create"""
        self.total_circuits = total_circuits

        self.max_outstanding = max_outstanding

        """per-guard statistics"""
        self.statistics = {}

        self.circuits_per_guard = math.ceil(float(self.total_circuits) / float(len(guards)))
        if self.circuits_per_guard < 1:
            raise RuntimeError("Not enough circuits (%d) for even one per guard (%d)." % (self.total_circuits, len(guards)))

        self.current_guard = None
        self.current_guard_circuits = 0
        self.last_circuit_extend = 0
        self.outstanding_circuits = []
        self._try_next_guard()

    def dump_statistics(self):
        print "statistics:"
        with open('stats.data', 'w') as statsfile:
            statsfile.write('#guard_id built failed success_rate create_errors NOPATH\n\n')

            for (hexid, stats) in self.statistics.items():
                print " ",hexid
                rate = 0.0
                if stats.success + stats.failure > 0:
                    rate = float(stats.failure) / float(stats.success + stats.failure)
                print "    built:",stats.success,"failed:",stats.failure,"failure rate:",(rate*100.0),"%",
                print "  errors=%d, NOPATH=%d" % (stats.errors, stats.nopath)

                statsfile.write('%s %d %d %f %d %d\n' % (hexid, stats.success, stats.failure, rate, stats.errors, stats.nopath))

    def _error(self, f):
        print "ERROR",f
        return f

    def _try_next_guard(self):
        """
        Set up Tor to use the next guard in the list, and reset our
        circuit count.
        """

        if len(self.guards) == 0:
            print "no more guards, we're done"
            ## note we registered a shutdown method to dump the
            ## statistics (which also works for ctrl-c for example)
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
        ##print "_setup_circuit():",arg

        # note 100% sure why I'm getting "551 Couldn't start circuit"
        # failures on creating a new circuit, but this waits at least
        # 2 seconds before doing another setup on two errors in a row
        if isinstance(arg, failure.Failure):
            self.statistics[self.current_guard].errors += 1

            timediff = self.reactor.seconds() - self.last_circuit_extend
            if timediff < 2.0:
                print arg.getErrorMessage(),
                print "-- waiting",(2.0 - timediff),"seconds"
                self.reactor.callLater(2.0 - timediff, self._setup_circuit, arg)
                return None

        elif arg and arg.split()[0] == 'EXTENDED':
            circid = int(arg.split()[1])
            if circid in self.outstanding_circuits:
                print "WEIRD, already have",circid,"in outstanding list."
            else:
                self.outstanding_circuits.append(circid)

            if len(self.outstanding_circuits) >= self.max_outstanding:
                return

        # tell Tor to build a new circuit, and we don't care about the
        # path. Since we've set only one guard, though, and
        # StrictNodes we should get a random (albeit tor-selected)
        # route using that guard.

        self.last_circuit_extend = self.reactor.seconds()
        d = self.protocol.queue_command("EXTENDCIRCUIT 0")
        d.addBoth(self._setup_circuit)
        return None

    def _increment_circuit_count(self):
        # we got notification about a circuit (built fine, or
        # failed). if we've tried enough for this guard already, go to
        # the next guard. if we're out of guards, that method will
        # dump stats and stop the reactor

        self.current_guard_circuits += 1
        print "We've tried",self.current_guard_circuits,"for guard",self.current_guard
        if self.current_guard_circuits >= self.circuits_per_guard:
            print "rotating guard"
            return self._try_next_guard()

    ## ICircuitListener API (only implementing the ones we want,
    ## thanks to CircuitListenerMixin)

    def circuit_built(self, circuit):
        print "BUILT",circuit
        build_again = False

        if circuit.id in self.outstanding_circuits:
            if len(self.outstanding_circuits) >= self.max_outstanding:
                build_again = True
            ##print "   found it",circuit.id
            self.outstanding_circuits.remove(circuit.id)

        if len(circuit.path) and circuit.path[0].id_hex == self.current_guard:
            ##print "DINGDINGDING!"
            self.statistics[self.current_guard].success += 1
            self._increment_circuit_count()

        print self.current_guard, "awaiting:", self.outstanding_circuits
        if build_again:
            return self._setup_circuit(None)

    def circuit_closed(self, circuit):
        pass

    def circuit_failed(self, circuit, reason):
        if reason == 'MEASUREMENT_FAILED':
            print "measurement failed, skipping failure",circuit
            return

        build_again = False

        if circuit.id in self.outstanding_circuits:
            if len(self.outstanding_circuits) >= self.max_outstanding:
                build_again = True
            self.outstanding_circuits.remove(circuit.id)

        if len(circuit.path) and circuit.path[0].id_hex[1:] == self.current_guard:
            self.statistics[self.current_guard].failure += 1
            self._increment_circuit_count()

        if reason == 'NOPATH':
            # presuming it's the current guard's circuit that failed...
            self.statistics[self.current_guard].nopath += 1

        print self.current_guard, "awaiting:", self.outstanding_circuits
        if build_again:
            return self._setup_circuit(None)

def setup(processprotocol):
    proto = processprotocol.tor_protocol
    state = txtorcon.TorState(proto)
    state.post_bootstrap.addCallback(really_setup).addErrback(setup_failed)

creator = None
def really_setup(state):
    print 'Connected to a Tor version %s' % state.protocol.version
    guards = state.guards.keys()
    global creator
    creator = CircuitCreator(reactor, state.protocol, guards[:10], 100, 5)
    print "circuits per guard:", creator.circuits_per_guard
    state.add_circuit_listener(creator)

def on_shutdown(*args):
    global creator
    if creator:
        print "shutting down, dumping statistics:"
        creator.dump_statistics()
reactor.addSystemEventTrigger('before', 'shutdown', on_shutdown)
    

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
