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
    # note that you can pass a few options as kwargs
    # (e.g. data_directory=, or socks_port= ). For other torrc
    # changes, see below.
    tor = yield txtorcon.launch(reactor, stdout=sys.stdout)
    print("Connected to Tor version '{}'".format(tor.protocol.version))

    state = yield tor.create_state()
    # or state = yield txtorcon.TorState.from_protocol(tor.protocol)

    print("This Tor has PID {}".format(state.tor_pid))
    print("This Tor has the following {} Circuits:".format(len(state.circuits)))
    for c in state.circuits.values():
        print("  {}".format(c))

    # for a couple of important options, we can pass them via
    # launch(..) above, but for anything else you access the
    # "TorConfig" instance and make any changes you like; all Tor
    # options are supported and you simply set them as
    # attributes.
    # *Changes are only sent to Tor when you call save()*
    print("Changing our config (SOCKSPort=[9876, 12345])")
    tor.config.SOCKSPort = [9876, 12345]
    yield tor.config.save()

    print("Querying to see it changed:")
    socksport = yield tor.protocol.get_conf("SOCKSPort")
    print("SOCKSPort={}".format(socksport))


if __name__ == '__main__':
    react(main)
