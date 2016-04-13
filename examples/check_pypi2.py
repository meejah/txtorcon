# just copying over most of "carml checkpypi" because it's a good
# example of "I want a stream over *this* circuit".

from __future__ import print_function

from urlparse import urlparse

from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import react
from twisted.internet.endpoints import UNIXClientEndpoint, HostnameEndpoint, TCP4ClientEndpoint
from twisted.web.iweb import IAgentEndpointFactory
from twisted.web.client import Agent, readBody
from zope.interface import implementer

import txtorcon
import txtorcon.socks


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


@implementer(IAgentEndpointFactory)
class AgentEndpointFactoryUsingTor(object):
    def __init__(self, reactor, tor_socks_endpoint):
        self._reactor = reactor
        self._proxy_ep = tor_socks_endpoint

    def endpointForURI(self, uri):
        print("URI", uri, uri.host, uri.port)
        # XXX tls=True/False
        return txtorcon.socks.TorSocksEndpoint(self._proxy_ep, uri.host, uri.port)


@inlineCallbacks
def main(reactor):
    ep = UNIXClientEndpoint(reactor, '/var/run/tor/control')
    tor = yield txtorcon.connect(reactor, ep)
    print("Connected:", tor)

    state = yield tor.create_state()
    print("State:", state)

    fac = AgentEndpointFactoryUsingTor(
        reactor, TCP4ClientEndpoint(reactor, '127.0.0.1', int(tor.config.SOCKSPort[0]))
    )
    agent = Agent.usingEndpointFactory(reactor, fac)
    uri = 'https://www.torproject.org:80'
    #uri = 'https://www.torproject.org:443'
    #uri = 'http://check.torproject.org/api/ip'
    import treq
    resp = yield treq.get(uri, agent=agent)
    print("Retrieving {} bytes".format(resp.length))
    data = yield resp.text()
    print("Data:\n{}".format(data))

# XXX WOOOOoo000t this works to :)

react(main)
