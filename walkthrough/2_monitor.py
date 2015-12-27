#!/usr/bin/env python

from __future__ import print_function
from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks, Deferred
from twisted.internet.endpoints import TCP4ClientEndpoint
from zope.interface import implementer
import txtorcon


@implementer(txtorcon.ICircuitListener)
class MyCircuitListener(object):

    def circuit_new(self, circuit):
        print("\n\n>> new", circuit)

    def circuit_launched(self, circuit):
        print("\n\n>> launched", circuit)

    def circuit_extend(self, circuit, router):
        print("\n\n>> extend", circuit)

    def circuit_built(self, circuit):
        print("\n\n>> built", circuit)

    def circuit_closed(self, circuit, **kw):
        print("\n\n>> closed", circuit, kw)

    def circuit_failed(self, circuit, **kw):
        print("\n\n>> failed", circuit, kw)


@inlineCallbacks
def main(reactor):
    # change the port to 9151 for Tor Browser Bundle
    tor_ep = TCP4ClientEndpoint(reactor, "localhost", 9051)
    connection = yield txtorcon.build_tor_connection(tor_ep, build_state=False)
    version = yield connection.get_info('version', 'events/names')
    print("Connected to Tor {version}".format(**version))
    print("Events:", version['events/names'])

    print("Building state.")
    state = yield txtorcon.TorState.from_protocol(connection)

    print("listening for circuit events")
    state.add_circuit_listener(MyCircuitListener())

    print("Issuing NEWNYM.")
    yield connection.signal('NEWNYM')
    print("OK.")

    print("Existing circuits:")
    for c in state.circuits.values():
        print(' ', c)

    print("listening for INFO events")
    def print_info(i):
        print("INFO:", i)
    connection.add_event_listener('INFO', print_info)

    done = Deferred()
    yield done  # never callback()s so infinite loop

react(main)
