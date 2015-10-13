#!/usr/bin/env python

# This connects to the system Tor (by default on control port 9151)
# and adds a new hidden service configuration to it.

from twisted.internet import defer
from twisted.internet.endpoints import TCP4ClientEndpoint, TCP4ServerEndpoint
from twisted.web import server, resource
from twisted.internet.task import react

import txtorcon


class Simple(resource.Resource):
    isLeaf = True

    def render_GET(self, request):
        return "<html>Hello, world! I'm a hidden service!</html>"


@defer.inlineCallbacks
def main(reactor):
    ep = TCP4ClientEndpoint(reactor, "localhost", 9251)
    tor_protocol = yield txtorcon.build_tor_connection(ep, build_state=False)
    print "Connected to Tor"
    tor_config = yield txtorcon.TorConfig.from_protocol(tor_protocol)

    print("existing services")
    for hs in tor_config.HiddenServices:
        print "HS", hs.hostname, hs.ports
    hs_public_port = 80
    hs_port = yield txtorcon.util.available_tcp_port(reactor)
    hs_string = '%s 127.0.0.1:%d' % (hs_public_port, hs_port)

    print("adding one", hs_port)
    onion = yield txtorcon.create_onion_service(
        reactor, tor_config, [hs_string],
        ephemeral=True,
        detach=False,
        discard_key=False,
    )

    print "Added ephemeral HS to Tor:", onion.hostname
    print "private key:"
    print onion.private_key

    print "Starting site"
    site = server.Site(Simple())
    hs_endpoint = TCP4ServerEndpoint(reactor, hs_port, interface='127.0.0.1')
    yield hs_endpoint.listen(site)

    # in 5 seconds, remove the hidden service -- obviously this is
    # where you'd do your "real work" or whatever.
    d = defer.Deferred()

    @defer.inlineCallbacks
    def remove():
        print "Removing the hiddenservice. Private key was"
        print hs.private_key
        yield hs.remove_from_tor(tor_protocol)
        d.callback(None)
    if False:
        reactor.callLater(5, remove)
        print "waiting 5 seconds"
    else:
        print "waiting forever"
        try:
            x = yield tor_protocol.get_info('onions/current')
            print "DING", x
        except Exception as e:
            print "error", e

        try:
            x = yield tor_protocol.get_info('onions/detached')
            print "DING", x
        except Exception as e:
            print "error", e

        print "our config says:"
        for hs in tor_config.EphemeralOnionServices:
            print "  ->", hs.hostname, hs.private_key
        for hs in tor_config.DetachedOnionServices:
            print "  ->", hs.hostname, hs.private_key

    yield d


react(main)
