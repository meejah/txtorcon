#!/usr/bin/env python

import os
from twisted.internet import reactor, defer
from twisted.internet.endpoints import TCP4ClientEndpoint
import txtorcon

@defer.inlineCallbacks
def launched(process_proto):
    """
    This callback gets called after Tor considers itself fully
    bootstrapped -- it has created a circuit. We get the
    TorProcessProtocol object, which has the TorControlProtocol
    instance as .tor_protocol
    """
    
    protocol = process_proto.tor_protocol
    print "Tor has launched.\nProtocol:", protocol
    info = yield protocol.get_info('traffic/read', 'traffic/written')
    print info
    reactor.stop()

def error(failure):
    print "There was an error", failure.getErrorMessage()
    reactor.stop()

def progress(percent, tag, summary):
    ticks = int((percent/100.0) * 10.0)
    prog = (ticks * '#') + ((10 - ticks) * '.')
    print '%s %s' % (prog, summary)

config = txtorcon.TorConfig()
config.ORPort = 0
config.SocksPort = 9999
try:
    os.mkdir('tor-data')
except OSError:
    pass
config.DataDirectory = './tor-data'

d = txtorcon.launch_tor(config, reactor, progress_updates=progress)
d.addCallback(launched).addErrback(error)

## this will only return after reactor.stop() is called
reactor.run()
