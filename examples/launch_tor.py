#!/usr/bin/env python

# Launch a slave Tor by first making a TorConfig object.

from sys import stdout
from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks
import txtorcon


@inlineCallbacks
def main(reactor):
    config = txtorcon.TorConfig()
    config.OrPort = 0  # could set this to be a relay, e.g. 1234
    config.SocksPort = [9999]
    try:
        yield txtorcon.launch_tor(config, reactor, stdout=stdout)

    except RuntimeError as e:
        print "Error:", e
        return

    proto = config.protocol
    print "Connected to Tor version", proto.version

    state = yield txtorcon.TorState.from_protocol(proto)
    print "This Tor has PID", state.tor_pid
    print "This Tor has the following %d Circuits:" % len(state.circuits)
    for c in state.circuits.values():
        print c

    # SOCKSPort is 'really' a list of SOCKS ports in Tor now, so we
    # have to set it to a list ... :/
    print "Changing our config (SOCKSPort=9876)"
    #config.SOCKSPort = ['unix:/tmp/foo/bar']
    config.SOCKSPort = ['9876']
    yield config.save()

    print "Querying to see it changed:"
    socksport = yield proto.get_conf("SOCKSPort")
    print "SOCKSPort", socksport


if __name__ == '__main__':
    react(main)
