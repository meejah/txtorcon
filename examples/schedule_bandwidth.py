#!/usr/bin/env python

##
## Here, we do something possible-useful and schedule changes to the
## "BandWidthRate" and optionally "BandWidthBurst" settings in Tor.
##

import os
import sys
import datetime
import stat

from twisted.python import log
from twisted.internet import reactor, defer
from twisted.internet.interfaces import IReactorTime
from twisted.internet.endpoints import UNIXClientEndpoint
from twisted.internet.endpoints import TCP4ClientEndpoint
from zope.interface import implements

from txtorcon import TorProtocolFactory, TorConfig

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
                self.bandwidth = 20*1024*1024
                self.burst = self.bandwidth
            yield (datetime.datetime.now() + datetime.timedelta(minutes=20), self.bandwidth, self.burst)

    def do_update(self):
        x = self.generator.next()
        future = x[0]
        self.new_bandwidth = x[1]
        self.new_burst = x[2]
        
        tm = (future - datetime.datetime.now()).seconds
        self.scheduler.callLater(tm, self.really_update)
        print "waiting",tm,"seconds to adjust bandwidth"

    def really_update(self):
        print "setting bandwidth + burst to",self.new_bandwidth,self.new_burst
        self.config.set_config('BandWidthBurst', self.new_burst, 'BandWidthRate', self.new_bandwidth)
        self.doUpdate()

def setup_complete(conf):
    print "Connected."
    bwup = BandwidthUpdater(conf, reactor)
    bwup.do_update()

def setup_failed(arg):
    print "SETUP FAILED",arg
    reactor.stop()

def bootstrap(proto):
    config = TorConfig(proto)
    config.post_bootstrap.addCallback(setup_complete).addErrback(setup_failed)
    print "Connection is live, bootstrapping config..."

if os.stat('/var/run/tor/control').st_mode & (stat.S_IRGRP | stat.S_IRUSR | stat.S_IROTH):
    print "using control socket"
    point = UNIXClientEndpoint(reactor, "/var/run/tor/control")
    
else:
    point = TCP4ClientEndpoint(reactor, "localhost", 9051)
    
d = point.connect(TorProtocolFactory())
d.addCallback(bootstrap).addErrback(setup_failed)
reactor.run()
