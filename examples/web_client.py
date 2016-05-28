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
    # ep = UNIXClientEndpoint(reactor, '/var/run/tor/control')
    ep = TCP4ClientEndpoint(reactor, '127.0.0.1', 9151)
    tor = yield txtorcon.connect(reactor, ep)
    print("Connected:", tor)

    # create a web.Agent that will talk via Tor. If the socks port
    # given isn't yet configured, this will do so (e.g. try something
    # else which definitely isn't already listening, like 9998)
    agent = tor.web_agent(u'9150')

    uri = 'https://www.torproject.org'
    print("Downloading {}".format(uri))
    resp = yield agent.request('GET', uri)

    print("Response has {} bytes".format(resp.length))
    body = yield readBody(resp)
    print("received body ({} bytes)".format(len(body)))
    print("{}\n[...]\n{}\n".format(body[:200], body[-200:]))


react(main)
