#!/usr/bin/env python

#
# This uses a very simple custom txtorcon.IStreamAttacher to disallow
# certain streams based solely on their port; by default it closes
# all streams on port 80 or 25 without ever attaching them to a
# circuit.
#
# For a more complex IStreamAttacher example, see
# attach_streams_by_country.py
#

from twisted.python import log
from twisted.internet import reactor
from zope.interface import implements

import txtorcon


def stream_closed(x):
    print "Stream closed:", x


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
            print "Disallowing", stream, "to port", stream.target_port
            d = self.state.close_stream(stream)
            d.addCallback(stream_closed)
            d.addErrback(log.err)
            return txtorcon.TorState.DO_NOT_ATTACH

        # Ask Tor to assign stream to a circuit by itself
        return None


def do_setup(state):
    print "Connected to a Tor version", state.protocol.version

    state.set_attacher(PortFilterAttacher(), reactor)

    print "Existing streams:"
    for s in state.streams.values():
        print ' ', s


def setup_failed(arg):
    print "SETUP FAILED", arg
    reactor.stop()


d = txtorcon.build_local_tor_connection(reactor)
d.addCallback(do_setup).addErrback(setup_failed)
reactor.run()
