#!/usr/bin/env python

##
## Launch a slave Tor by first making a TorConfig object.
##

import sys
import types

from twisted.python import log
from twisted.internet import reactor, defer
from zope.interface import implements

import txtorcon

def state_complete(state):
    print "We've completely booted up a TorState to a Tor version %s at PID %d" % (state.protocol.version, state.tor_pid)

    print "This Tor has the following %d Circuits:" % len(state.circuits)
    for c in state.circuits.values():
        print c
    
    print "We could now do any sort of exciting thing we wanted..."
    print "...but instead, we'll just exit."
    reactor.stop()

def setup_complete(proto):
    print "setup complete:",proto
    print "Building a TorState"
    state = txtorcon.TorState(proto.tor_protocol)
    state.post_bootstrap.addCallback(state_complete)
    state.post_bootstrap.addErrback(setup_failed)

def setup_failed(arg):
    print "SETUP FAILED",arg
    reactor.stop()

def bootstrap(c):
    conf = TorConfig(c)
    conf.post_bootstrap.addCallback(setup_complete).addErrback(setup_failed)
    print "Connection is live, bootstrapping state..."

config = txtorcon.TorConfig()
config.OrPort = 1234
config.SocksPort = 9999

def updates(prog, tag, summary):
    print "%d%%: %s" % (prog, summary)

d = txtorcon.launch_tor(config, reactor, progress_updates=updates)
d.addCallback(setup_complete)
d.addErrback(setup_failed)
reactor.run()
