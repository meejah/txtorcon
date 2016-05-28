#!/usr/bin/env python

# This connects to the system Tor (by default on control port 9151)
# and adds a new hidden service configuration to it.

from twisted.internet import defer
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.web import server, resource
from twisted.internet.task import react

import txtorcon


class Simple(resource.Resource):
    isLeaf = True

    def render_GET(self, request):
        return "<html>Hello, world! I'm a hidden service!</html>"


@defer.inlineCallbacks
def main(reactor):
    tor = yield txtorcon.connect(
        reactor,
        TCP4ClientEndpoint(reactor, "localhost", 9251)
    )

    print("existing services")
    for hs in tor.config.HiddenServices:
        print "HS", hs.hostname, hs.ports

    hs_endpoint = tor.create_onion_endpoint(80)
    site = server.Site(Simple())
    yield hs_endpoint.listen(site)

    # in 5 seconds, remove the hidden service -- obviously this is
    # where you'd do your "real work" or whatever.
    d = defer.Deferred()

    @defer.inlineCallbacks
    def remove():
        print "Removing the hiddenservice. Private key was"
        print hs.private_key
        yield hs.remove_from_tor(tor.protocol)
        d.callback(None)
    if False:
        reactor.callLater(5, remove)
        print "waiting 5 seconds"
    else:
        print "waiting forever"
        try:
            x = yield tor.protocol.get_info('onions/current')
            print "DING", x
        except Exception as e:
            print "error", e

        try:
            x = yield tor.protocol.get_info('onions/detached')
            print "DING", x
        except Exception as e:
            print "error", e

        print "our config says:"
        for hs in tor.config.EphemeralOnionServices:
            print "  ->", hs.hostname, hs.private_key
        for hs in tor.config.DetachedOnionServices:
            print "  ->", hs.hostname, hs.private_key

    yield d


react(main)
