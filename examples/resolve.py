#!/usr/bin/env python

from __future__ import print_function
from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks
from twisted.internet.endpoints import TCP4ClientEndpoint
import txtorcon


@inlineCallbacks
def main(reactor):
    ep = TCP4ClientEndpoint(reactor, "localhost", 9051)
    print("Connecting via '{}'".format(ep))
    tor = yield txtorcon.connect(reactor, ep)
    print("Connected to tor:", tor)

    for uri in ['torproject.org']:
        print("RESOLVE '{}'...".format(uri))
        answer = yield tor.dns_resolve(uri)
        print("'{}' resolves to '{}'".format(uri, answer))

        print("RESOLVE_PTR '{}'".format(answer))
        rev = yield tor.dns_resolve_ptr(answer)
        print("'{}' reverses to '{}'".format(answer, rev))


react(main)
