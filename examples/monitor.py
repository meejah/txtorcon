#!/usr/bin/env python

##
## Just listens for a few EVENTs from Tor (INFO NOTICE WARN ERR) and
## prints out the contents, so functions like a log monitor.
##

from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint
import txtor

def log(msg):
    print msg

def setup(proto):
    print "Connected to a Tor version",proto.version
    for event in ['INFO', 'NOTICE', 'WARN', 'ERR']:
        proto.add_event_listener(event, log)

def setup_failed(arg):
    print "SETUP FAILED",arg
    reactor.stop()

d = txtor.build_tor_connection(TCP4ClientEndpoint(reactor, "localhost", 9051), buildstate=False)
d.addCallback(setup).addErrback(setup_failed)
reactor.run()
