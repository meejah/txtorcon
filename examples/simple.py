from __future__ import print_function
# a "simple" example, using the highest-level protocol the
# "controller" stuff.

import os
import sys
from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks, Deferred
import txtorcon


@inlineCallbacks
def main(reactor):
    tor = yield txtorcon.launch(
        reactor,
        data_directory="/tmp/torstuff",
        stdout=sys.stdout,  # see tor startup messages
    )
    print("Tor has been launched")

    for x in tor.config:
        print("  {}: {}".format(x, getattr(tor.config, x)))
    print("SOCKS listener at localhost:{}".format(tor.config.SOCKSPort))

    print("Test me by running:")
    print("curl --socks5-hostname localhost:{} https://check.torproject.org/api/ip".format(tor.config.SOCKSPort))
    yield Deferred()  # wait forever

if __name__ == '__main__':
    react(main)

