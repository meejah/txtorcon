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


@implementer(IAgentEndpointFactory)
class AgentEndpointFactoryForCircuit(object):
    def __init__(self, reactor, circ):
        self._reactor = reactor
        self._circ = circ

    def endpointForURI(self, uri):
        """IAgentEndpointFactory API"""
        print("URI", uri, uri.host, uri.port)
##        return txtorcon.TorClientEndpoint(uri.host, uri.port)
        # XXX host will be *!@#F#$ bytes on py3
        return self._circ.stream_to(self._reactor, uri.host, uri.port, use_tls=True)


@inlineCallbacks
def main(reactor):
    ep = UNIXClientEndpoint(reactor, '/var/run/tor/control')
    tor = yield txtorcon.connect(reactor, ep)
    print("Connected:", tor)

    state = yield tor.create_state()
    print("State:", state)

    circ = yield state.build_circuit()
    yield circ.when_built()
    print("Built:", circ)
    fac = AgentEndpointFactoryForCircuit(reactor, circ)
    agent = Agent.usingEndpointFactory(reactor, fac)
    resp = yield agent.request('GET', 'https://www.torproject.org:443')
    print("req", resp, dir(resp))
    body = yield readBody(resp)
    print("body {} bytes".format(len(body)))

# XXX fuck yeah! this works now ...

react(main)
