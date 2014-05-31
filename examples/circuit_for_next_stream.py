#!/usr/bin/env python

#
# This allows you to create a particular circuit, which is then used
# for the very next (non-Tor-internal) stream created. The use-case
# here might be something like, "I'm going to connect a long-lived
# stream in a moment *cough*IRC*cough*, so I'd like a circuit through
# high-uptime nodes"
#

import sys
import functools
import random

from twisted.python import log
from twisted.internet import reactor
from zope.interface import implements

import txtorcon


class MyStreamListener(txtorcon.StreamListenerMixin):

    def stream_new(self, stream):
        print "new stream:", stream.id, stream.target_host

    def stream_succeeded(self, stream):
        print "successful stream:", stream.id, stream.target_host


class MyAttacher(txtorcon.CircuitListenerMixin, txtorcon.StreamListenerMixin):
    implements(txtorcon.IStreamAttacher)

    def __init__(self, state):
        self.state = state
        # the circuit which we will use to attach the next stream to
        self.circuit = None

    def set_circuit(self, circuit):
        self.circuit = circuit

    def circuit_built(self, circuit):
        "ICircuitListener"

        if self.circuit is None:
            return

        if circuit != self.circuit:
            return

        print "Circuit built, awaiting next stream."

    def attach_stream(self, stream, circuits):
        """
        IStreamAttacher API
        """

        if self.circuit is not None:
            print "Attaching", stream, "to", self.circuit
            return self.circuit

        # let Tor connect this stream how it likes
        return None

    def stream_attach(self, stream, circuit):
        print "stream", stream.id, "attached to circuit", circuit.id,
        print "with path:", '->'.join(map(lambda x: x.location.countrycode,
                                          circuit.path))
        if self.circuit is circuit:
            print "...so we're done."
            reactor.stop()


def do_setup(path, state):
    print "Connected to a Tor version", state.protocol.version

    attacher = MyAttacher(state)
    state.set_attacher(attacher, reactor)
    state.add_circuit_listener(attacher)
    state.add_stream_listener(attacher)

    print "Existing state when we connected:"
    print "Streams:"
    for s in state.streams.values():
        print ' ', s

    print
    print "General-purpose circuits:"
    for c in filter(lambda x: x.purpose == 'GENERAL', state.circuits.values()):
        path = '->'.join(map(lambda x: x.location.countrycode, c.path))
        print ' ', c.id, path

    print "Building our Circuit:", path
    real_path = []
    try:
        for name in path:
            print name
            if name == 'X':
                if len(real_path) == 0:
                    g = random.choice(state.entry_guards.values())
                    real_path.append(g)

                else:
                    g = random.choice(state.routers.values())
                    real_path.append(g)

            else:
                real_path.append(state.routers[name])

    except KeyError, e:
        print "Couldn't find router:", e
        sys.exit(1)

    print "...using routers:", real_path
    d = state.build_circuit(real_path)
    d.addCallback(attacher.set_circuit).addErrback(log.err)
    return d


def setup_failed(arg):
    print "Setup Failed:", arg.getErrorMessage()
    reactor.stop()

if len(sys.argv) == 1:
    print "usage: %s router [router] [router] ..." % sys.argv[0]
    print
    print "       You may use X for a router name, in which case a random one will"
    print "       be selected (a random one of your entry guards if its in the first"
    print "       position)."
    sys.exit(1)

path = sys.argv[1:]

d = txtorcon.build_local_tor_connection(reactor)
d.addCallback(functools.partial(do_setup, path)).addErrback(setup_failed)
reactor.run()
