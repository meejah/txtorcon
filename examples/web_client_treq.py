# just copying over most of "carml checkpypi" because it's a good
# example of "I want a stream over *this* circuit".

from __future__ import print_function

from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import react
from twisted.internet.endpoints import UNIXClientEndpoint
from twisted.web.iweb import IAgentEndpointFactory
from zope.interface import implementer

import txtorcon

try:
    import treq
except ImportError:
    print("To use this example, please install 'treq':")
    print("pip install treq")
    raise SystemExit(1)


@inlineCallbacks
def main(reactor):
    ep = UNIXClientEndpoint(reactor, '/var/run/tor/control')
    tor = yield txtorcon.connect(reactor, ep)
    print("Connected:", tor)

    agent = tor.web_agent('9875')
    uri = 'https://www.torproject.org:443'
    resp = yield treq.get(uri, agent=agent)

    print("Retrieving {} bytes".format(resp.length))
    data = yield resp.text()
    print("Got {} bytes:\n{}\n[...]{}".format(len(data), data[:120], data[-120:]))

react(main)
