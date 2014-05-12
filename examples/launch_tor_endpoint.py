#!/usr/bin/env python

##
## Here we set up a Twisted Web server and then launch a slave tor
## with a configured hidden service directed at the Web server we set
## up. This uses serverFromString to translate the "onion" endpoint descriptor
## into a TCPHiddenServiceEndpoint object...
##

import shutil

from twisted.internet import reactor
from twisted.web import server, resource
from twisted.internet.endpoints import serverFromString

import txtorcon


class Simple(resource.Resource):
    isLeaf = True

    def render_GET(self, request):
        return "<html>Hello, world! I'm a hidden service!</html>"

site = server.Site(Simple())


def setup_failed(arg):
    print "SETUP FAILED", arg


def setup_complete(port):
    print "Received an IListeningPort %s" % (port,)
    print "..whose `getHost` gives us a %s" % port.getHost()


def progress(percent, tag, message):
    bar = int(percent / 10)
    print '[%s%s] %s' % ('#' * bar, '.' * (10 - bar), message)

hs_endpoint = serverFromString(reactor, "onion:80")
#hs_endpoint = serverFromString(reactor, "onion:80:controlPort=9089:localPort=8080")
#hs_endpoint = serverFromString(reactor, "onion:80:controlPort=9089:localPort=8080:hiddenServiceDir=/home/human/src/txtorcon/hidserv")

d = hs_endpoint.listen(site)
d.addCallbacks(setup_complete, setup_failed)

reactor.run()
