# this example shows how to use Twisted's web client with Tor via
# txtorcon

from __future__ import print_function

from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import react
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.web.client import readBody

import txtorcon


@inlineCallbacks
def main(reactor):
    # use port 9051 for system tor instances, or:
    # ep = UNIXClientEndpoint(reactor, '/var/run/tor/control')
    ep = TCP4ClientEndpoint(reactor, '127.0.0.1', 9151)
    tor = yield txtorcon.connect(reactor, ep)
    print("Connected:", tor)

    state = yield tor.create_state()
    socks = tor.config.socks_endpoint(reactor, u"9150")

    # create a custom circuit; in this case we're just letting Tor
    # decide the path -- but this could be done several other ways
    # e.g. with txtorcon.CircuitBuilder
    circ = yield state.build_circuit()
    print("Building a circuit:", circ)

    # at this point, the circuit will be "under way" but may not yet
    # be in BUILT state -- and hence usable. So, we wait.
    yield circ.when_built()
    print("Circuit is ready:", circ)

    # create a web.Agent that will use this circuit (or fail)
    agent = circ.web_agent(reactor, socks)

    uri = 'https://www.torproject.org'
    print("Downloading {}".format(uri))
    resp = yield agent.request('GET', uri)

    print("Response has {} bytes".format(resp.length))
    body = yield readBody(resp)
    print("received body ({} bytes)".format(len(body)))
    print("{}\n[...]\n{}\n".format(body[:200], body[-200:]))


react(main)
