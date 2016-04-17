# just copying over most of "carml checkpypi" because it's a good
# example of "I want a stream over *this* circuit".

from __future__ import print_function

from urlparse import urlparse

from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import react
from twisted.internet.endpoints import UNIXClientEndpoint, HostnameEndpoint
from twisted.web.iweb import IAgentEndpointFactory
from twisted.web.client import Agent, readBody
from zope.interface import implementer

import txtorcon


@inlineCallbacks
def main(reactor):
    ep = UNIXClientEndpoint(reactor, '/var/run/tor/control')
    tor = yield txtorcon.connect(reactor, ep)
    print("Connected:", tor)

    state = yield tor.create_state()
    print("State:", state)

    # only new tors
    #socks = yield tor.config.socks_endpoint("unix:/tmp/foo/socks")
    socks = yield tor.config.socks_endpoint(reactor, "9998")

    circ = yield state.build_circuit()
    yield circ.when_built()
    print("Built:", circ)
    if False:
        # any circuit Tor likes
        agent = tor.web_agent('unix:/tmp/foo/socks')
    else:
        # this very circuit we created
        #agent = yield circ.web_agent(reactor, tor.config, 'unix:/tmp/foo/socks')
        agent = circ.web_agent(reactor, socks)
    print("agent", agent)
    resp = yield agent.request('GET', 'https://www.torproject.org')
    print("Response has {} bytes".format(resp.length))
    body = yield readBody(resp)
    print("received body ({} bytes)".format(len(body)))
    print("{}\n[...]\n{}\n".format(body[:200], body[-200:]))

# XXX fuck yeah! this works now ...

react(main)
