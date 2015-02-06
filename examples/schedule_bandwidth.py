#!/usr/bin/env python

# Here, we do something possible-useful and schedule changes to the
# "BandWidthRate" and optionally "BandWidthBurst" settings in Tor.

import datetime
from twisted.internet import reactor
from twisted.internet.interfaces import IReactorTime
from txtorcon import build_local_tor_connection, TorConfig


class BandwidthUpdater:

    def __init__(self, config, scheduler):
        self.bandwidth = 0
        self.config = config
        self.scheduler = IReactorTime(scheduler)
        self.generator = self.next_update()

    def next_update(self):
        """
        Generator that gives out the next time to do a bandwidth update,
        as well as what the new bandwidth value should be. Here, we toggle
        the bandwidth every 20 minutes.
        """

        while True:
            if self.bandwidth:
                self.bandwidth = 0
                self.burst = 0
            else:
                self.bandwidth = 20 * 1024 * 1024
                self.burst = self.bandwidth
            yield (datetime.datetime.now() + datetime.timedelta(minutes=20),
                   self.bandwidth, self.burst)

    def do_update(self):
        x = self.generator.next()
        future = x[0]
        self.new_bandwidth = x[1]
        self.new_burst = x[2]

        tm = (future - datetime.datetime.now()).seconds
        self.scheduler.callLater(tm, self.really_update)
        print "waiting", tm, "seconds to adjust bandwidth"

    def really_update(self):
        print "setting bandwidth + burst to", self.new_bandwidth, self.new_burst
        self.config.set_config('BandWidthBurst', self.new_burst,
                               'BandWidthRate', self.new_bandwidth)
        self.doUpdate()


def setup_complete(conf):
    print "Connected."
    bwup = BandwidthUpdater(conf, reactor)
    bwup.do_update()


def setup_failed(arg):
    print "SETUP FAILED", arg
    reactor.stop()


def bootstrap(proto):
    config = TorConfig(proto)
    config.post_bootstrap.addCallback(setup_complete).addErrback(setup_failed)
    print "Connection is live, bootstrapping config..."


d = build_local_tor_connection(reactor, build_state=False,
                               wait_for_proto=False)
d.addCallback(bootstrap).addErrback(setup_failed)

reactor.run()
