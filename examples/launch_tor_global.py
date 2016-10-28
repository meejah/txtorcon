from __future__ import print_function

"""
Use the 'global_tor' instance from txtorcon; this is a Tor
instance that either doesn't exist or is unique to this process'
txtorcon library (i.e. a singleton for this process)
"""

import sys
import txtorcon
from twisted.web.client import readBody
from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks
from twisted.internet.endpoints import clientFromString


@inlineCallbacks
def main(reactor):
    tor = yield txtorcon.get_global_tor(reactor)
    # note that you can pass a few options as kwargs
    # (e.g. data_directory=, or socks_port= ). For other torrc
    # changes, see below.
    tor = yield txtorcon.launch(reactor, data_directory="./tordata", stdout=sys.stdout, socks_port='unix:/tmp/tor2/socks')
    #tor = yield txtorcon.connect(reactor, clientFromString(reactor, "unix:/var/run/tor/control"))
    print("Connected to Tor version '{}'".format(tor.protocol.version))

    state = yield tor.create_state()
    # or state = yield txtorcon.TorState.from_protocol(tor.protocol)

    print("This Tor has PID {}".format(state.tor_pid))
    print("This Tor has the following {} Circuits:".format(len(state.circuits)))
    for c in state.circuits.values():
        print("  {}".format(c))

    agent = tor.web_agent(u'unix:/tmp/tor2/socks')
    uri = 'https://www.torproject.org'
    print("Downloading {}".format(uri))
    resp = yield agent.request('GET', uri)
    print("Response has {} bytes".format(resp.length))
    body = yield readBody(resp)
    print("received body ({} bytes)".format(len(body)))
    print("{}\n[...]\n{}\n".format(body[:200], body[-200:]))


if __name__ == '__main__':
    react(main)
