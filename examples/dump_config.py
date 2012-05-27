#!/usr/bin/env python

##
## Simple usage example of TorConfig
##

import os
import sys
import stat
import types

from twisted.python import log
from twisted.internet import reactor, defer
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.endpoints import UNIXClientEndpoint
from zope.interface import implements

from txtorcon import TorProtocolFactory, TorConfig, DEFAULT_VALUE

def setup_complete(config):
    print "Got config"
    keys = config.config.keys()
    keys.sort()
    defaults = []
    for k in keys:
        if k == 'HiddenServices':
            for hs in config.config[k]:
                for xx in ['dir', 'version', 'authorize_client']:
                    if getattr(hs, xx):
                        print 'HiddenService%s %s' % (xx.capitalize(), getattr(hs, xx))
                for port in hs.ports:
                    print 'HiddenServicePort',port
            continue

        v = getattr(config, k)
        if isinstance(v, types.ListType):
            for val in v:
                if val != DEFAULT_VALUE:
                    print k,val
                    
        elif v == DEFAULT_VALUE:
            defaults.append(k)
            
        else:
            print k,v

    if 'defaults' in sys.argv:
        print "Set to default value:"
        for k in defaults:
            print "# %s" % k
            
    reactor.stop()
    
def setup_failed(arg):
    print "SETUP FAILED",arg
    reactor.stop()

def bootstrap(c):
    conf = TorConfig(c)
    conf.post_bootstrap.addCallback(setup_complete).addErrback(setup_failed)
    print "Connection is live, bootstrapping state..."

if os.stat('/var/run/tor/control').st_mode & (stat.S_IRGRP | stat.S_IRUSR | stat.S_IROTH):
    print "using control socket"
    point = UNIXClientEndpoint(reactor, "/var/run/tor/control")
    
else:
    point = TCP4ClientEndpoint(reactor, "localhost", 9051)
    
d = point.connect(TorProtocolFactory())
# do not use addCallbacks() here, in case bootstrap has an error
d.addCallback(bootstrap).addErrback(setup_failed)
reactor.run()
