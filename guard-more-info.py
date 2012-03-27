#!/usr/bin/env python

import string

from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint

import txtorcon

def setup(state):
    lines = open('failed.csv','r').readlines()
    output = open('failed-augmented.csv', 'w')
    output.write(lines[0].strip() + ', guard_bandwidth, exit_bandwidth\n')
    for line in lines[1:]:
        line = map(string.strip, line.split(','))
        guard_id = line[0]
        exit_id = line[2]
        try:
            output.write(','.join(line) + ', %d, %d\n' % (state.routers[guard_id].bandwidth, state.routers[exit_id].bandwidth))
        except KeyError:
            print "Can't find guard or exit:",line
            continue
    output.close()

def setup_failed(arg):
    print "SETUP FAILED",arg
    print arg
    reactor.stop()

def update(percent, tag, summary):
    print "  %d%% %s" % (int(percent), summary)

print "Connecting to localhost:9051"
config = txtorcon.TorConfig()
d = txtorcon.build_tor_connection(TCP4ClientEndpoint(reactor, "localhost", 9051))
d.addCallback(setup).addErrback(setup_failed)
reactor.run()
