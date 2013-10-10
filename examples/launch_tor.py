#!/usr/bin/env python

##
## Launch a slave Tor by first making a TorConfig object.
##

import functools
from twisted.internet import reactor
import txtorcon


def finished(answer):
    print "Answer:", answer
    print "We could now do any sort of exciting thing we wanted..."
    print "...but instead, we'll just exit."
    reactor.stop()


def query_changed_config(answer, state):
    # now we'll ask for the ORPort back to prove it changed
    state.protocol.get_conf("ORPort").addCallback(finished)


def state_complete(config, state):
    print "We've completely booted up a TorState to a Tor version %s at PID %d" % (state.protocol.version, state.tor_pid)

    print "This Tor has the following %d Circuits:" % len(state.circuits)
    for c in state.circuits.values():
        print c

    config.SOCKSPort = 0
    config.ORPort = 9089
    # "save" may be poorly-named API; it serializes the options to the
    # running Tor (via SETCONF calls)
    config.save().addCallback(query_changed_config, state)


def setup_complete(config, proto):
    print "setup complete:", proto
    print "Building a TorState"
    state = txtorcon.TorState(proto.tor_protocol)
    # Pass the config object yet again, avoiding global state
    state.post_bootstrap.addCallback(functools.partial(state_complete, config))
    state.post_bootstrap.addErrback(setup_failed)


def setup_failed(arg):
    print "SETUP FAILED", arg
    reactor.stop()


def updates(prog, tag, summary):
    print "%d%%: %s" % (prog, summary)


config = txtorcon.TorConfig()
config.OrPort = 1234
config.SocksPort = 9999


# Launch tor. The config-object is passed by the closure around
# setup_complete()
d = txtorcon.launch_tor(config, reactor, progress_updates=updates)
d.addCallback(functools.partial(setup_complete, config))
d.addErrback(setup_failed)
reactor.run()
