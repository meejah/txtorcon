#!/usr/bin/env python

from __future__ import print_function
from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks
from twisted.internet.endpoints import TCP4ClientEndpoint
import txtorcon

@inlineCallbacks
def main(reactor):
    # change the port to 9151 for Tor Browser Bundle
    connection = TCP4ClientEndpoint(reactor, "localhost", 9051)

    state = yield txtorcon.build_tor_connection(connection)
    print("Connected to tor {state.protocol.version}".format(state=state))
    print("Current circuits:")
    for circ in state.circuits.values():
        path = '->'.join([r.name for r in circ.path])
        print("  {circ.id}: {circ.state}, {path}".format(circ=circ, path=path))

    # can also do "low level" things with the protocol
    proto = state.protocol
    answer = yield proto.queue_command("GETINFO version")
    print("GETINFO version: {answer}".format(answer=answer))

react(main)
