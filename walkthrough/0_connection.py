#!/usr/bin/env python

from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint
import txtorcon

def example(state):
    """
    This callback gets called after we've connected and loaded all the
    current Tor state.
    """
    print "Fully bootstrapped state:", state
    print "   with bootstrapped protocol:", state.protocol
    reactor.stop()

## change the port to 9151 for Tor Browser Bundle
connection = TCP4ClientEndpoint(reactor, "localhost", 9051)

d = txtorcon.build_tor_connection(connection)
d.addCallback(example)

## this will only return after reactor.stop() is called
reactor.run()
