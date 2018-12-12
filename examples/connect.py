#!/usr/bin/env python

from __future__ import print_function
from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks
from twisted.internet.endpoints import TCP4ClientEndpoint
import txtorcon


@react
@inlineCallbacks
def main(reactor):
    ep = TCP4ClientEndpoint(reactor, "localhost", 9051)
    # or (e.g. on Debian):
    # ep = UNIXClientEndpoint(reactor, "/var/run/tor/control")
    tor = yield txtorcon.connect(reactor, ep)
    print("Connected to Tor {version}".format(version=tor.protocol.version))

    d = tor.protocol.when_disconnected()

    def its_gone(value):
        print("Connection gone")
    d.addCallback(its_gone)

    tor.protocol.transport.loseConnection()
    yield d
