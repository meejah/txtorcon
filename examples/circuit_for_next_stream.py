#!/usr/bin/env python

##
## This allows you to create a particular circuit, which is then used
## for the very next (non-Tor-internal) stream created. The use-case
## here might be something like, "I'm going to connect a long-lived
## stream in a moment *cough*IRC*cough*, so I'd like a circuit through
## high-uptime nodes"
##

import os
import sys
import stat
import functools

from twisted.python import log
from twisted.internet import reactor, defer
from twisted.internet.endpoints import UNIXClientEndpoint
from twisted.internet.endpoints import TCP4ClientEndpoint
from zope.interface import implements

import txtorcon

class MyStreamListener(txtorcon.StreamListenerMixin):
    
    def stream_new(self, stream):
        print "new stream:",stream.id,stream.target_host
    
    def stream_succeeded(self, stream):
        print "successful stream:",stream.id,stream.target_host
    


class MyAttacher(txtorcon.CircuitListenerMixin, txtorcon.StreamListenerMixin):
    implements(txtorcon.IStreamAttacher)

    def __init__(self, state):
        self.state = state
        ## the circuit which we will use to attach the next stream to
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
        print "stream",stream.id,"attached to circuit",circuit.id, \
              "with path:",'->'.join(map(lambda x: x.location.countrycode, circuit.path))
        if self.circuit is circuit:
            print "...so we're done."
            reactor.stop()

def do_setup(path, state):
    print "Connected to a Tor version",state.protocol.version

    attacher = MyAttacher(state)
    state.set_attacher(attacher, reactor)
    state.add_circuit_listener(attacher)
    state.add_stream_listener(attacher)

    print "Existing state when we connected:"
    print "Streams:"
    for s in state.streams.values():
        print ' ',s

    print
    print "General-purpose circuits:"
    for c in filter(lambda x: x.purpose == 'GENERAL', state.circuits.values()):
        print ' ',c.id,'->'.join(map(lambda x: x.location.countrycode, c.path))

    print "Building our Circuit:", path
    path = map(lambda x: state.routers[x], path)
    print "...using routers:", path
    return state.build_circuit(path).addCallback(attacher.set_circuit).addErrback(log.err)

def setup_failed(arg):
    print "SETUP FAILED",arg
    reactor.stop()

point = TCP4ClientEndpoint(reactor, "localhost", 9051)

if len(sys.argv) == 1:
    print "usage: %s router [router] [router] ..." % sys.argv[0]
    sys.exit(1)

path = sys.argv[1:]
    
d = txtorcon.build_tor_connection(point)
d.addCallback(functools.partial(do_setup, path)).addErrback(setup_failed)
reactor.run()
