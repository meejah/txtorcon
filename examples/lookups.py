from __future__ import print_function

from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks
from twisted.internet.endpoints import clientFromString
from twisted.web.client import Agent
import txtorcon
from txtorcon import socks

class _AgentEndpointFactoryUsingTor(object):
    def __init__(self, reactor, ep):
        self._reactor = reactor
        self._proxy_ep = ep

    def endpointForURI(self, uri):
        print("creating torsocksep for", uri)
        return socks.TorSocksEndpoint(
            self._proxy_ep,
            uri.host,
            uri.port,
            tls=(uri.scheme == b'https'),
        )


@inlineCallbacks
def main(reactor):
    tor_ep = clientFromString(reactor, "tcp:localhost:9050")
    if False:
        for domain in [u'www.torproject.org', u'meejah.ca']:
            print("Looking up '{}' via Tor".format(domain))
            ans = yield socks.resolve(tor_ep, domain)
            print("...got answer: {}".format(ans))
            print("Doing PTR on {}".format(ans))
            ans = yield socks.resolve_ptr(tor_ep, ans)
            print("...got answer: {}".format(ans))

    ep = txtorcon.TorClientEndpoint(
        'www.torproject.org', 80,
        socks_endpoint=tor_ep,
    )
    factory = _AgentEndpointFactoryUsingTor(reactor, ep)
    agent = Agent.usingEndpointFactory(reactor, factory)
    reply = yield agent.request('GET', 'https://www.torproject.org')
    print("reply", reply)


if __name__ == '__main__':
    react(main)
