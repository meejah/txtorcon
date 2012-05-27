#!/usr/bin/env python

##
## This uses a very simple custom txtorcon.IStreamAttacher to disallow
## certain streams based solely on their port; by default it closes
## all streams on port 80 or 25 without ever attaching them to a
## circuit.
##
## For a more complex IStreamAttacher example, see
## attach_streams_by_country.py
##

import os
import sys
import stat
import random

from twisted.python import log
from twisted.internet import reactor, defer
from twisted.internet.endpoints import UNIXClientEndpoint
from twisted.internet.endpoints import TCP4ClientEndpoint
from zope.interface import implements

import txtorcon

def stream_closed(x):
    print "Stream closed:",x

class PortFilterAttacher:
    implements(txtorcon.IStreamAttacher)

    def __init__(self, state):
        self.state = state
        self.disallow_ports = [80, 25]
        print "Disallowing all streams to ports:",
        print ",".join(map(str, self.disallow_ports))
    
    def attach_stream(self, stream, circuits):
        """
        IStreamAttacher API
        """

        if stream.target_port in self.disallow_ports:
            print "Disallowing",stream
            self.state.close_stream(stream).addCallback(stream_closed).addErrback(log.err)
            return self.state.DO_NOT_ATTACH

        # Ask Tor to assign stream to a circuit by itself
        return None

def do_setup(state):
    print "Connected to a Tor version",state.protocol.version

    attacher = PortFilterAttacher(state)
    state.set_attacher(attacher, reactor)

    print "Existing streams:"
    for s in state.streams.values():
        print ' ',s

def setup_failed(arg):
    print "SETUP FAILED",arg
    reactor.stop()

if os.stat('/var/run/tor/control').st_mode & (stat.S_IRGRP | stat.S_IRUSR | stat.S_IROTH):
    print "using control socket"
    point = UNIXClientEndpoint(reactor, "/var/run/tor/control")
    
else:
    point = TCP4ClientEndpoint(reactor, "localhost", 9051)
    
d = txtorcon.build_tor_connection(point)
d.addCallback(do_setup).addErrback(setup_failed)
reactor.run()
