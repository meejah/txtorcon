#!/usr/bin/env python

from __future__ import print_function
from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks
from twisted.internet.endpoints import TCP4ClientEndpoint
import txtorcon

@inlineCallbacks
def main(reactor):
    tor = yield txtorcon.connect(reactor, TCP4ClientEndpoint(reactor, "localhost", 9051))

    tpo = yield tor.dns_resolve('torproject.org')
    print("'torproject.org' resolves to '{}'".format(tpo))

    rev = yield tor.dns_resolve_ptr(tpo)
    print("'{}' reverses to '{}'".format(tpo, rev))

react(main)
