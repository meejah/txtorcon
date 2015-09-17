#!/usr/bin/env python

from twisted.internet import reactor, defer
from twisted.internet.endpoints import TCP4ClientEndpoint
from zope.interface import implements
import txtorcon

## change the port to 9151 for Tor Browser Bundle
connection = TCP4ClientEndpoint(reactor, "localhost", 9051)

def error(failure):
    print "Error:", failure.getErrorMessage()
    reactor.stop()

class MyCircuitListener(object):
    implements(txtorcon.ICircuitListener)
    @staticmethod
    def circuit_new(circuit):
        print "new", circuit

    @staticmethod
    def circuit_launched(circuit):
        print "launched", circuit

    @staticmethod
    def circuit_extend(circuit, router):
        print "extend", circuit

    @staticmethod
    def circuit_built(circuit):
        print "built", circuit

    @staticmethod
    def circuit_closed(circuit, **kw):
        print "closed", circuit, kw

    @staticmethod
    def circuit_failed(circuit, **kw):
        print "failed", circuit, kw


@defer.inlineCallbacks
def main(connection):
    version = yield connection.get_info('version', 'events/names')
    print "Connected to Tor.", version['version']
    print version['events/names']

    print "Issuing NEWNYM."
    yield connection.signal('NEWNYM')
    print "OK."

    print "Building state."
    state = txtorcon.TorState(connection)
    yield state.post_bootstrap
    print "State initialized."
    print "Existing circuits:"
    for c in state.circuits.values():
        print ' ', c

    print "listening for circuit events"
    state.add_circuit_listener(MyCircuitListener())

    print "listening for INFO events"
    def print_info(i):
        print "INFO:", i
    connection.add_event_listener('INFO', print_info)

    ## since we don't call reactor.stop(), we keep running

d = txtorcon.build_tor_connection(connection, build_state=False)
d.addCallback(main).addErrback(error)

## this will only return after reactor.stop() is called
reactor.run()
