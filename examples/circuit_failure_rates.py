#!/usr/bin/env python

#
# This example uses ICircuitListener to monitor how many circuits have
# failed since the monitor started up. If this figure is more than 50%,
# a warning-level message is logged.
#
# Like the :ref:`stream_circuit_logger.py` example, we also log all new
# circuits.
#

import functools
import sys
import time
from twisted.internet import reactor, task
from twisted.python import usage
import txtorcon


class Options(usage.Options):
    """
    command-line options we understand
    """

    optParameters = [
        ['failed', 'f', 0, 'Starting value for number of failed circuits.',
         int],
        ['built', 'b', 0,
         'Starting value for the total number of built cicuits.', int],
        ['connect', 'c', None, 'Tor control socket to connect to in '
         'host:port format, like "localhost:9051" (the default).'],
        ['delay', 'n', 60, 'Seconds to wait between status updates.', int]]

    def __init__(self):
        usage.Options.__init__(self)
        self['guards'] = []
        self.docs['guard'] = 'Specify the name, built and failed rates ' \
            'like "SomeTorNode,10,42". Can be specified multiple times.'

    def opt_guard(self, value):
        name, built, failed = value.split(',')
        self['guards'].append((name, int(built), int(failed)))


class CircuitFailureWatcher(txtorcon.CircuitListenerMixin):

    built_circuits = 0
    failed_circuits = 0
    percent = 0.0
    failed_circuit_ids = []
    per_guard_built = {}
    per_guard_failed = {}

    def print_update(self):
        print time.ctime(reactor.seconds()) + ': ' + self.information()

    def update_percent(self):
        self.percent = 100.0 * (float(self.failed_circuits) /
                                float(self.built_circuits +
                                      self.failed_circuits))
        if self.percent > 50.0:
            print 'WARNING: %02.1f percent of all routes' % self.percent
            print ' have failed: %d failed, %d built' % (self.failed_circuits,
                                                         self.built_circuits)

    def information(self):
        rtn = '%02.1f%% of all circuits' % self.percent
        rtn += 'have failed: %d failed, %d built' % (self.failed_circuits,
                                                     self.built_circuits)
        for g in self.per_guard_built.keys():
            per_guard_percent = 100.0 * (self.per_guard_failed[g] /
                                         (self.per_guard_built[g] +
                                          self.per_guard_failed[g]))
            current = ' '
            for guard in self.state.entry_guards.values():
                if g == guard.name or g == guard.id_hex:
                    current = '*'
                    break
            rtn = rtn + '\n %s %s: %d built, %d failed: %02.1f%%' % \
                (current,
                 g,
                 self.per_guard_built[g],
                 self.per_guard_failed[g],
                 per_guard_percent)
        return rtn

    def circuit_built(self, circuit):
        """ICircuitListener API"""
        # older tor versions will have empty build_flags
        if 'ONEHOP_TUNNEL' in circuit.build_flags:
            return

        if circuit.purpose == 'GENERAL':
            if len(circuit.path) > 0:
                if circuit.path[0] not in self.state.entry_guards.values():
                    print "WEIRD: first circuit hop not in entry guards:",
                    print circuit, circuit.path, circuit.purpose
                    return

            self.built_circuits += 1
            self.update_percent()

            if len(circuit.path) != 3 and len(circuit.path) != 4:
                print "WEIRD: circuit has odd pathlength:",
                print circuit, circuit.path
            try:
                self.per_guard_built[circuit.path[0].unique_name] += 1.0
            except KeyError:
                self.per_guard_built[circuit.path[0].unique_name] = 1.0
                self.per_guard_failed[circuit.path[0].unique_name] = 0.0

    def circuit_failed(self, circuit, kw):
        """ICircuitListener API"""

        if kw['REASON'] != 'MEASUREMENT_EXPIRED':
            return

        # older tor versions will have empty build_flags
        if 'ONEHOP_TUNNEL' in circuit.build_flags:
            return

        if circuit.purpose == 'GENERAL':
            if len(circuit.path) > 1:
                if circuit.path[0] not in self.state.entry_guards.values():
                    # note that single-hop circuits are built for various
                    # internal reasons (and it seems they somtimes use
                    # GENERAL anyway)
                    print "WEIRD: first circuit hop not in entry guards:",
                    print circuit, circuit.path
                    return

            self.failed_circuits += 1
            print "failed", circuit.id
            if circuit.id not in self.failed_circuit_ids:
                self.failed_circuit_ids.append(circuit.id)
            else:
                print "WARNING: duplicate message for", circuit

            if len(circuit.path) > 0:
                try:
                    self.per_guard_failed[circuit.path[0].unique_name] += 1.0
                except KeyError:
                    self.per_guard_failed[circuit.path[0].unique_name] = 1.0
                    self.per_guard_built[circuit.path[0].unique_name] = 0.0

            self.update_percent()


def setup(options, listener, state):
    print 'Connected to a Tor version', state.protocol.version,
    print 'at', state.protocol.transport.addr

    listener.failed_circuits = int(options['failed'])
    listener.built_circuits = int(options['built'])
    listener.state = state  # FIXME use ctor (ditto for options, probably)
    for name, built, failed in options['guards']:
        listener.per_guard_built[name] = float(built)
        listener.per_guard_failed[name] = float(failed)

    for circ in filter(lambda x: x.purpose == 'GENERAL',
                       state.circuits.values()):
        if circ.state == 'BUILT':
            listener.circuit_built(circ)
    state.add_circuit_listener(listener)
    # print an update every minute
    task.LoopingCall(listener.print_update).start(options['delay'])


def setup_failed(arg):
    print "SETUP FAILED", arg
    print arg
    reactor.stop()


options = Options()
try:
    options.parseOptions(sys.argv[1:])
except usage.UsageError:
    print "This monitors circuit failure rates on multi-hop PURPOSE_GENERAL circuits only."
    print "Tor internally uses other circuit types or GENERAL single-hop circuits for"
    print "internal use and we try to ignore these."
    print
    print "Every minute, the summary is printed out. For each entry-guard your Tor is"
    print "currently using, a separate count and summary is printed."
    print
    print "Nothing is saved to disc. If you wish to start again with the same totals"
    print "as a previous run, use the options below. On exit, a command-line suitable"
    print "to do this is printed."
    print
    print options.getUsage()
    sys.exit(-1)


def on_shutdown(listener, *args):
    print '\nTo carry on where you left off, run:'
    print '  %s --failed %d --built %d' % (sys.argv[0],
                                           listener.failed_circuits,
                                           listener.built_circuits),
    for name in listener.per_guard_built.keys():
        print '--guard %s,%d,%d' % (name, listener.per_guard_built[name],
                                    listener.per_guard_failed[name]),
    print

listener = CircuitFailureWatcher()

reactor.addSystemEventTrigger('before', 'shutdown',
                              functools.partial(on_shutdown, listener))

if options['connect']:
    host, port = options['connect'].split(':')
    port = int(port)
    print 'Connecting to %s:%i...' % (host, port)
    d = txtorcon.build_local_tor_connection(reactor, host=host, port=port)
else:
    d = txtorcon.build_local_tor_connection(reactor)
d.addCallback(functools.partial(setup, options, listener))
d.addErrback(setup_failed)

reactor.run()
