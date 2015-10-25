#!/usr/bin/env python

# This connects to the system Tor (by default on control port 9151)
# and adds a new hidden service configuration to it.

import os
import functools
import shutil

from twisted.internet import reactor, defer
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

    hs_public_port = 80
    hs_port = yield txtorcon.util.available_tcp_port(reactor)
    hs_string = '%s 127.0.0.1:%d' % (hs_public_port, hs_port)
    print "Adding ephemeral service", hs_string
    print "(this can take some time; please be patient)"
    hs = txtorcon.EphemeralHiddenService([hs_string])
    yield hs.add_to_tor(tor_protocol)
    print "Added ephemeral HS to Tor:", hs.hostname

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
    yield d


react(main)
