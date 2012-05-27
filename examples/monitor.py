#!/usr/bin/env python

##
## Just listens for a few EVENTs from Tor (INFO NOTICE WARN ERR) and
## prints out the contents, so functions like a log monitor.
##

import os
import stat
from twisted.internet import reactor
from twisted.internet.endpoints import UNIXClientEndpoint
from twisted.internet.endpoints import TCP4ClientEndpoint
import txtorcon

def log(msg):
    print msg

def setup(proto):
    print "Connected to a Tor version",proto.version
    for event in ['INFO', 'NOTICE', 'WARN', 'ERR']:
        proto.add_event_listener(event, log)

def setup_failed(arg):
    print "SETUP FAILED",arg
    reactor.stop()

if os.stat('/var/run/tor/control').st_mode & (stat.S_IRGRP | stat.S_IRUSR | stat.S_IROTH):
    print "using control socket"
    point = UNIXClientEndpoint(reactor, "/var/run/tor/control")
    
else:
    point = TCP4ClientEndpoint(reactor, "localhost", 9051)
    
d = txtorcon.build_tor_connection(point, build_state=False)
d.addCallback(setup).addErrback(setup_failed)
reactor.run()
