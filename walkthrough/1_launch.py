#!/usr/bin/env python

from __future__ import print_function
import os
from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import react
from twisted.internet.endpoints import TCP4ClientEndpoint
import txtorcon

def progress(percent, tag, summary):
    """
    Progress update from tor; we print a cheezy progress bar and the
    message.
    """
    ticks = int((percent/100.0) * 10.0)
    prog = (ticks * '#') + ((10 - ticks) * '.')
    print('{} {}'.format(prog, summary))

@inlineCallbacks
def main(reactor):
    config = txtorcon.TorConfig()
    config.ORPort = 0
    config.SocksPort = 9998
    try:
        os.mkdir('tor-data')
    except OSError:
        pass
    config.DataDirectory = './tor-data'

    try:
        process = yield txtorcon.launch_tor(
            config, reactor, progress_updates=progress
        )
    except Exception as e:
        print("Error launching tor:", e)
        return

    protocol = process.tor_protocol
    print("Tor has launched.")
    print("Protocol:", protocol)
    info = yield protocol.get_info('traffic/read', 'traffic/written')
    print(info)

    # explicitly stop tor by either disconnecting our protocol or the
    # Twisted IProcessProtocol (or just exit our program)
    print("Killing our tor, PID={pid}".format(pid=process.transport.pid))
    yield process.transport.signalProcess('TERM')

react(main)
