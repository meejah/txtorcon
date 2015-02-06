#!/usr/bin/env python

# Just listens for a few EVENTs from Tor (INFO NOTICE WARN ERR) and
# prints out the contents, so functions like a log monitor.

from twisted.internet import reactor
import txtorcon


def log(msg):
    print msg


def setup(proto):
    print "Connected to a Tor version", proto.version
    for event in ['INFO', 'NOTICE', 'WARN', 'ERR']:
        proto.add_event_listener(event, log)
    proto.get_info('status/version/current', 'version').addCallback(log)


def setup_failed(arg):
    print "SETUP FAILED", arg
    reactor.stop()

d = txtorcon.build_local_tor_connection(reactor, build_state=False)
d.addCallback(setup).addErrback(setup_failed)
reactor.run()
