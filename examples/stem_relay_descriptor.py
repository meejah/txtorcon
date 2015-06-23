#!/usr/bin/env python

# This shows how to get the detailed information about a
# relay descriptor and parse it into Stem's Relay Descriptor
# class. More about the class can be read from
#
# https://stem.torproject.org/api/descriptor/server_descriptor.html#stem.descriptor.server_descriptor.RelayDescriptor
#
# We need to pass the nickname or the fingerprint of the onion
# router for which we need the the descriptor information,

from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks
import txtorcon


@inlineCallbacks
def main(reactor):
    proto = yield txtorcon.build_local_tor_connection(reactor, build_state=False)

    or_nickname = "moria1"
    print "Trying to get decriptor information about", or_nickname
    # If the fingerprint is used in place of nickname then, desc/id/<OR identity>
    # should be used.
    descriptor_info = yield proto.get_info('desc/name/' + or_nickname)

    descriptor_info = descriptor_info['desc/name/' + or_nickname]
    try:
        from stem.descriptor.server_descriptor import RelayDescriptor
        relay_info = RelayDescriptor(descriptor_info) 
        print "The relay's fingerprint is:", relay_info.fingerprint
        print "Time in UTC when the descriptor was made:", relay_info.published
    except ImportError as e:
        print "Error:", e


if __name__ == '__main__':
    react(main)
