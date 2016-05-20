from __future__ import print_function

"""
Launch a private Tor instance.
"""

import sys
import txtorcon
from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks


@inlineCallbacks
def main(reactor):
    tor = yield txtorcon.launch(reactor, stdout=sys.stdout)
    print("Connected to Tor version '{}'".format(tor.protocol.version))

    state = yield tor.create_state()
    # or state = yield txtorcon.TorState.from_protocol(tor.protocol)
    
    print("This Tor has PID {}".format(state.tor_pid))
    print("This Tor has the following {} Circuits:".format(len(state.circuits)))
    for c in state.circuits.values():
        print("  {}".format(c))

    print("Changing our config (SOCKSPort=9876)")
    tor.config.SOCKSPort = [9876, 12345]
    yield tor.config.save()

    print("Querying to see it changed:")
    socksport = yield tor.protocol.get_conf("SOCKSPort")
    print("SOCKSPort={}".format(socksport))


if __name__ == '__main__':
    react(main)
