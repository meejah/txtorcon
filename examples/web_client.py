# this example shows how to use Twisted's web client with Tor via
# txtorcon

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

    # create a web.Agent that will talk via Tor. If the socks port
    # 9998 isn't yet configured, this will do so.
    agent = tor.web_agent(u'9998')

    uri = 'https://www.torproject.org'
    print("Downloading {}".format(uri))
    resp = yield agent.request('GET', uri)

    print("Response has {} bytes".format(resp.length))
    body = yield readBody(resp)
    print("received body ({} bytes)".format(len(body)))
    print("{}\n[...]\n{}\n".format(body[:200], body[-200:]))


react(main)
