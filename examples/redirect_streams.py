from __future__ import print_function

# Uses the IStreamAttacher interface to show how to use custom logic
# to attach streams to circuits.

import random

from twisted.internet import defer
from twisted.internet.task import react
from zope.interface import implementer

import txtorcon


@implementer(txtorcon.IStreamAttacher)
class MyAttacher(object):

    def __init__(self, state):
        # reference to our TorState object
        self.state = state

    def attach_stream_failure(self, stream, f):
        print("Attaching failed for {}: {}".format(stream, f))

#    @defer.inlineCallbacks
    def attach_stream(self, stream, circuits):
        """
        IStreamAttacher API
        """

        # note, this method can be async if required (and of course
        # you can still interact with Tor in the meantime). You can't
        # attach streams going to hidden-services (see Tor bug
        # XXX). Tor may reject your choice -- in which case you should
        # get a call to attach_stream_failure() with the Failure

        print("Attaching stream: {}".format(stream))

        if random.choice([0, 1]):
            print("  Letting Tor attach it")
            return None

        circ = random.choice(circuits.values())
        print(
            "  using circuit {circuit.id}: {path} {circuit.purpose}".format(
                circuit=circ,
                path='->'.join([r.location.countrycode for r in circ.path]),
            )
        )
        return circ


@defer.inlineCallbacks
def main(reactor):
    tor = yield txtorcon.connect(reactor)  # connects to a default control-port
    print("Connected to a Tor version", tor.protocol.version)
    state = yield tor.create_state()

    attacher = MyAttacher(state)
    yield state.add_attacher(attacher, reactor)

    print("Existing state when we connected:")
    print("Streams:")
    for s in state.streams.values():
        print('  {}'.format(s))

    print()
    print("General-purpose circuits:")
    for c in filter(lambda x: x.purpose == 'GENERAL', state.circuits.values()):
        print(
            '  {} {}'.format(
                c.id,
                '->'.join([r.location.countrycode for r in c.path]),
            )
        )
    yield defer.Deferred()

if __name__ == '__main__':
    react(main)
