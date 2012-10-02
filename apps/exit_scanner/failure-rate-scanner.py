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
import random

from twisted.internet import reactor, task
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.python import usage, failure
from zope.interface import implements

import txtorcon

PRINT_ERRORS = False

class Options(usage.Options):

    optFlags = [
        ['launch', 'L', 'Launch a new Tor process for the scan, rather than connecting to an existing one.']
        ]

    optParameters = [
        ['guards', 'G', 0, 'Total number of Guards to choose (takes the first N from the consensus). 0 means all.', int],
        ['circuits', 'C', 0, 'Total number of circuits to set up (distributed evenly over Guards).', int],
        ['circuits-per-guard', 'c', 10, 'Circuits per guard to set up; takes precedent over --circuits.', int],
        ['address', 'a', "localhost:9051", 'Tor control socket to connect to in host:port format.'],
        ['max-outstanding', 'x', 10, "Maximum number of circuits we'll ask Tor to build at one time.", int]
        ]

    def __init__(self):
        usage.Options.__init__(self)

    def postOptions(self):
        ## FIXME is there a way to tell if the user specified an
        ## option, versus getting the default? i.e. we want to throw
        ## even if the user did: --launch --address localhost:9051
        if self.opts.has_key('launch') and self.opts['address'] != 'localhost:9051':
            raise RuntimeError("Doesn't make sense to specify both --launch and --address")


class GuardStatistics:
    id_hex = ''
    failure = 0
    success = 0
    errors = 0
    nopath = 0
    guard = None                        # will be Router instance

    def failure_rate(self):
        rate = 0.0
        if self.success + self.failure > 0:
            rate = float(self.failure) / float(self.success + self.failure)
        return rate


class CircuitCreator(txtorcon.CircuitListenerMixin):

    def __init__(self, reactor, tor_protocol, guards, total_circuits, max_outstanding):
        """
        :param tor_protocol:
            (a TorControlProtocol instance) must be bootstrapped
            already

        :param guards:
            list of Guard nodes (Router instances) to use.

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
        self.statistics = {}            # key is router hex-id

        self.circuits_per_guard = math.ceil(float(self.total_circuits) / float(len(guards)))
        if self.circuits_per_guard < 1:
            raise RuntimeError("Not enough circuits (%d) for even one per guard (%d)." % (self.total_circuits, len(guards)))

        self.current_guard = None
        self.current_guard_circuits = 0
        self.last_circuit_extend = 0
        self.outstanding_circuits = []
        self.outstanding_deferreds = []
        self.completed_circuits = []
        self._try_next_guard()

    @staticmethod
    def dump_statistic(stats):
        print " ", stats.guard.id_hex, stats.guard.unique_name
        rate = stats.failure_rate()
        print "    built:",stats.success,"failed:",stats.failure,"failure rate:",(rate*100.0),"%",
        print "  errors=%d, NOPATH=%d" % (stats.errors, stats.nopath)
        return rate

    def dump_statistics(self):
        with open('stats.data', 'w') as statsfile:
            statsfile.write('#guard_unique_name guard_id built failed success_rate guard_bandwidth create_errors NOPATH\n\n')

            for (hexid, stats) in self.statistics.items():
                rate = stats.failure_rate()
                statsfile.write('%s %s %d %d %f %f %d %d\n' % (stats.guard.unique_name, hexid, stats.success, stats.failure, rate, stats.guard.bandwidth, stats.errors, stats.nopath))

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
            if len(self.outstanding_deferreds):
                return
            reactor.stop()
            return

        self.current_guard = self.guards[0]
        self.current_guard_circuits = 0
        self.guards = self.guards[1:]
        gs = GuardStatistics()
        gs.guard = self.current_guard
        self.statistics[self.current_guard.id_hex] = gs

        sys.stdout.write('%42s ' % self.current_guard.unique_name)
        sys.stdout.flush()
        d = self.protocol.set_conf("StrictNodes", 1, "EntryNodes", str(self.current_guard.id_hex))
        d.addCallback(self._setup_circuit).addErrback(self._error)
        return d

    def _setup_circuit(self, arg):
        ##print "_setup_circuit():",arg

        # note 100% sure why I'm getting "551 Couldn't start circuit"
        # failures on creating a new circuit, but this waits at least
        # 2 seconds before doing another setup on two errors in a row
        if isinstance(arg, failure.Failure):
            self.statistics[self.current_guard.id_hex].errors += 1

            timediff = self.reactor.seconds() - self.last_circuit_extend
            if timediff < 2.0:
                if PRINT_ERRORS:
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

        if self.current_guard_circuits + len(self.outstanding_circuits) >= self.circuits_per_guard:
            ##print "already requested enough"
            return

        self.last_circuit_extend = self.reactor.seconds()
        d = self.protocol.queue_command("EXTENDCIRCUIT 0")
        self.outstanding_deferreds.append(d)
        d.addBoth(self._remove_completed_deferred, d)
        d.addBoth(self._setup_circuit)
        return None

    def _remove_completed_deferred(self, arg, d):
        ##print "remove",arg
        self.outstanding_deferreds.remove(d)
        return arg

    def _increment_circuit_count(self):
        # we got notification about a circuit (built fine, or
        # failed). if we've tried enough for this guard already, go to
        # the next guard. if we're out of guards, that method will
        # dump stats and stop the reactor

        self.current_guard_circuits += 1
        ##print "We've tried",self.current_guard_circuits,"for guard",self.current_guard.unique_name
        if self.current_guard_circuits >= self.circuits_per_guard:
            ##print "rotating guard"
            stat = self.statistics[self.current_guard.id_hex]
            print ' %d/%d failed; %3.1f%% failure-rate' % (stat.failure, stat.success+stat.failure, stat.failure_rate()*100.0)
            self.dump_statistics()
            return self._try_next_guard()

    ## ICircuitListener API (only implementing the ones we want,
    ## thanks to CircuitListenerMixin)

    def circuit_built(self, circuit):
        #print "BUILT",circuit
        build_again = False

        if circuit.id in self.outstanding_circuits:
            if len(self.outstanding_circuits) >= self.max_outstanding:
                build_again = True
            ##print "   found it",circuit.id
            self.outstanding_circuits.remove(circuit.id)
            self.completed_circuits.append(circuit.id)

        else:
            if circuit.id in self.completed_circuits:
                msg = "ERROR? got a BUILT after being done with a circuit: %s\n" % str(circuit)
                print msg,
                sys.stderr.write(msg)

        if len(circuit.path) and circuit.path[0].id_hex == self.current_guard.id_hex:
            ##print "DINGDINGDING!"
            self.statistics[self.current_guard.id_hex].success += 1
            sys.stdout.write('.')
            sys.stdout.flush()
            self._increment_circuit_count()

        ##print self.current_guard.unique_name, "awaiting:", self.outstanding_circuits
        if build_again:
            return self._setup_circuit(None)

    def circuit_closed(self, circuit):
        pass

    def circuit_failed(self, circuit, reason):
        if reason == 'MEASUREMENT_FAILED':
            print "measurement failed, skipping failure",circuit
            return

        build_again = False
        ##print "FAIL", reason, circuit.id, '->'.join(map(lambda x: x.unique_name, circuit.path))

        if circuit.id in self.outstanding_circuits:
            if len(self.outstanding_circuits) >= self.max_outstanding:
                build_again = True
            self.outstanding_circuits.remove(circuit.id)
            self.statistics[self.current_guard.id_hex].failure += 1
            sys.stdout.write('F')
            sys.stdout.flush()
            self._increment_circuit_count()

        else:
            if circuit.id in self.completed_circuits:
                msg = "ERROR? got a FAILED after being done with a circuit: %s\n" % str(circuit)
                print msg,
                sys.stderr.write(msg)

        if reason == 'NOPATH':
            # presuming it's the current guard's circuit that failed...
            self.statistics[self.current_guard.id_hex].nopath += 1

        ##print self.current_guard.unique_name, "awaiting:", self.outstanding_circuits
        if build_again:
            return self._setup_circuit(None)

def setup(processprotocol, options):
    proto = processprotocol.tor_protocol
    state = txtorcon.TorState(proto)
    state.post_bootstrap.addCallback(really_setup, options).addErrback(setup_failed)

creator = None
def really_setup(state, options):
    print 'Connected to a Tor version %s' % state.protocol.version
    guards = state.guards.values()
    random.shuffle(guards)

    # FIXME should probably randomize the guard node order in a
    # cryptographically secure fasion.

    global creator
    if options['guards'] > 0:
        guards = guards[:options['guards']]

    total_circuits = options['circuits']
    if options['circuits-per-guard']:
        total_circuits = len(guards) * options['circuits-per-guard']

    print "Attempting with %d guards over %d circuits." % (len(guards), total_circuits)

    creator = CircuitCreator(reactor, state.protocol, guards, total_circuits, options['max-outstanding'])
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

if __name__ == '__main__':
    try:
        options = Options()
        options.parseOptions(sys.argv[1:])

        if options['launch']:
            print "Launching new Tor instance:"
            config = txtorcon.TorConfig()
            # FIXME could make this better (e.g. random, and/or check if it's taken first)
            config.SOCKSPort = 9999
            config.ControlPort = 1234
            d = txtorcon.launch_tor(config, reactor, progress_updates=update)
            d.addCallback(setup, options).addErrback(setup_failed)

        else:
            host, port = options['address'].split(':')
            d = txtorcon.build_tor_connection(TCP4ClientEndpoint(reactor, host, int(port)))
            d.addCallback(really_setup, options).addErrback(setup_failed)

        reactor.run()

    except usage.UsageError:
        print options.getUsage()
        sys.exit(-1)

    except Exception, e:
        print options.getUsage()
        print "ERROR:",e
        sys.exit(-2)
