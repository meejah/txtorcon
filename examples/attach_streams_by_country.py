#!/usr/bin/env python

#
# This uses a custom txtorcon.IStreamAttacher to force streams to use
# circuits that exit in the same country (as supplied by GeoIP) and
# builds such a circuit if one isn't available yet.
#
# Note that you can do something very similar to this with Tor's
# config file as well by setting something like:
#
# ExitNodes {us},{ca}
#
# ...in your torrc. The above just exits from those countries, not
# the one in which the Web server is located, however. So, this is a
# little redundant, but gives you the idea of how to do these sorts
# of things.
#
# Another thing to note is that the DNS lookup is a stream before the
# name is looked up, so the DNS lookup may occur from whatever stream
# Tor chose for that (we return None, which causes the attacher to
# tell Tor to attach that stream itself). This presents a problem for
# sites which optimize the server they deliver based on DNS -- if you
# lookup from X you'll get a server near/in X, which for our next
# step will make "the site" appear to be there.
#
# The only "solution" for this would be to do the lookup locally, but
# that defeats the purpose of Tor.
#

import random

from twisted.python import log
from twisted.internet import reactor, defer
from zope.interface import implements

import txtorcon


class MyStreamListener(txtorcon.StreamListenerMixin):

    def stream_new(self, stream):
        print "new stream:", stream.id, stream.target_host

    def stream_succeeded(self, stream):
        print "successful stream:", stream.id, stream.target_host

    def stream_attach(self, stream, circuit):
        print "stream", stream.id, " attached to circuit", circuit.id,
        print "with path:", '->'.join(map(lambda x: x.location.countrycode,
                                          circuit.path))


class MyAttacher(txtorcon.CircuitListenerMixin):
    implements(txtorcon.IStreamAttacher)

    def __init__(self, state):
        # pointer to our TorState object
        self.state = state
        # circuits for which we are awaiting completion so we can
        # finish our attachment to them.
        self.waiting_circuits = []

    def waiting_on(self, circuit):
        for (circid, d, stream_cc) in self.waiting_circuits:
            if circuit.id == circid:
                return True
        return False

    def circuit_extend(self, circuit, router):
        "ICircuitListener"
        if circuit.purpose != 'GENERAL':
            return
        # only output for circuits we're waiting on
        if self.waiting_on(circuit):
            path = '->'.join(map(lambda x: x.location.countrycode,
                                 circuit.path))
            print "  circuit %d (%s). Path now %s" % (circuit.id,
                                                      router.id_hex,
                                                      path)

    def circuit_built(self, circuit):
        "ICircuitListener"
        if circuit.purpose != 'GENERAL':
            return

        path = '->'.join(map(lambda r: r.location.countrycode,
                             circuit.path))
        print "circuit built", circuit.id, path
        for (circid, d, stream_cc) in self.waiting_circuits:
            if circid == circuit.id:
                self.waiting_circuits.remove((circid, d, stream_cc))
                d.callback(circuit)

    def circuit_failed(self, circuit, kw):
        if self.waiting_on(circuit):
            print "A circuit we requested", circuit.id,
            print "has failed. Reason:", kw['REASON']

            circid, d, stream_cc = None, None, None
            for x in self.waiting_circuits:
                if x[0] == circuit.id:
                    circid, d, stream_cc = x
            if d is None:
                raise Exception("Expected to find circuit.")

            self.waiting_circuits.remove((circid, d, stream_cc))
            print "Trying a new circuit build for", circid
            self.request_circuit_build(stream_cc, d)

    def attach_stream(self, stream, circuits):
        """
        IStreamAttacher API
        """
        if stream.target_host not in self.state.addrmap.addr:
            print "No AddrMap entry for", stream.target_host,
            print "so I don't know where it exits; get Tor to attach stream."
            return None

        ip = str(self.state.addrmap.addr[stream.target_host].ip)
        stream_cc = txtorcon.util.NetLocation(ip).countrycode
        print "Stream to", ip, "exiting in", stream_cc

        if stream_cc is None:
            # returning None tells TorState to ask Tor to select a
            # circuit instead
            print "   unknown country, Tor will assign stream"
            return None

        for circ in circuits.values():
            if circ.state != 'BUILT' or circ.purpose != 'GENERAL':
                continue

            circuit_cc = circ.path[-1].location.countrycode
            if circuit_cc is None:
                print "warning: don't know where circuit", circ.id, "exits"

            if circuit_cc == stream_cc:
                print "  found suitable circuit:", circ
                return circ

        # if we get here, we haven't found a circuit that exits in
        # the country GeoIP claims our target server is in, so we
        # need to build one.
        print "Didn't find a circuit, building one"

        # we need to return a Deferred which will callback with our
        # circuit, however built_circuit only callbacks with the
        # message from Tor saying it heard about our request. So when
        # that happens, we push our real Deferred into the
        # waiting_circuits list which will get pop'd at some point
        # when the circuit_built() listener callback happens.

        d = defer.Deferred()
        self.request_circuit_build(stream_cc, d)
        return d

    def request_circuit_build(self, stream_cc, deferred_to_callback):
        # for exits, we can select from any router that's in the
        # correct country.
        last = filter(lambda x: x.location.countrycode == stream_cc,
                      self.state.routers.values())

        # start with an entry guard, put anything in the middle and
        # put one of our exits at the end.
        path = [random.choice(self.state.entry_guards.values()),
                random.choice(self.state.routers.values()),
                random.choice(last)]

        print "  requesting a circuit:", '->'.join(map(lambda r:
                                                       r.location.countrycode,
                                                       path))

        class AppendWaiting:
            def __init__(self, attacher, d, stream_cc):
                self.attacher = attacher
                self.d = d
                self.stream_cc = stream_cc

            def __call__(self, circ):
                """
                return from build_circuit is a Circuit. However, we
                want to wait until it is built before we can issue an
                attach on it and callback to the Deferred we issue
                here.
                """
                print "  my circuit is in progress", circ.id
                self.attacher.waiting_circuits.append((circ.id, self.d,
                                                       self.stream_cc))

        d = self.state.build_circuit(path)
        d.addCallback(AppendWaiting(self, deferred_to_callback, stream_cc))
        d.addErrback(log.err)
        return d


def do_setup(state):
    print "Connected to a Tor version", state.protocol.version

    attacher = MyAttacher(state)
    state.set_attacher(attacher, reactor)
    state.add_circuit_listener(attacher)

    state.add_stream_listener(MyStreamListener())

    print "Existing state when we connected:"
    print "Streams:"
    for s in state.streams.values():
        print ' ', s

    print
    print "General-purpose circuits:"
    for c in filter(lambda x: x.purpose == 'GENERAL', state.circuits.values()):
        print ' ', c.id, '->'.join(map(lambda x: x.location.countrycode,
                                       c.path))


def setup_failed(arg):
    print "SETUP FAILED", arg
    reactor.stop()

d = txtorcon.build_local_tor_connection(reactor)
d.addCallback(do_setup).addErrback(setup_failed)
reactor.run()
