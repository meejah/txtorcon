#!/usr/bin/env python

# Here we set up a Twisted Web server and then launch a slave tor
# with a configured hidden service directed at the Web server we set
# up. This uses serverFromString to translate the "onion" endpoint descriptor
# into a TCPHiddenServiceEndpoint object...

from twisted.internet import reactor
from twisted.web import server, resource
from twisted.internet.endpoints import serverFromString

import txtorcon


class Simple(resource.Resource):
    isLeaf = True

    def render_GET(self, request):
        return "<html>Hello, world! I'm a hidden service!</html>"


def setup_failed(arg):
    print "SETUP FAILED", arg


def setup_complete(port):
    # the port we get back should implement this (as well as IListeningPort)
    port = txtorcon.IHiddenService(port)
    print "I have set up a hidden service, advertised at:",
    print "http://%s:%d" % (port.getHost().onion_uri, port.getHost().onion_port)
    print "locally listening on", port.local_address.getHost()
    print "Will stop in 60 seconds..."

    def blam(x):
        print "%d..." % x
    reactor.callLater(50, blam, 10)
    reactor.callLater(55, blam, 5)
    reactor.callLater(56, blam, 4)
    reactor.callLater(57, blam, 3)
    reactor.callLater(58, blam, 2)
    reactor.callLater(59, blam, 1)
    reactor.callLater(60, reactor.stop)


def progress(percent, tag, message):
    bar = int(percent / 10)
    print '[%s%s] %s' % ('#' * bar, '.' * (10 - bar), message)

# several ways to proceed here and what they mean:
#
# ep0:
#    launch a new Tor instance, configure a hidden service on some
#    port and pubish descriptor for port 80
# ep1:
#    connect to existing Tor via control-port 9051, configure a hidden
#    service listening locally on 8080, publish a descriptor for port
#    80 and use an explicit hiddenServiceDir (where "hostname" and
#    "private_key" files are put by Tor). We set SOCKS port
#    explicitly, too.
# ep2:
#    all the same as ep1, except we launch a new Tor (because no
#    "controlPort=9051")
#

ep0 = "onion:80"
ep1 = "onion:80:controlPort=9051:localPort=8080:socksPort=9089:hiddenServiceDir=/home/human/src/txtorcon/hidserv"
ep2 = "onion:80:localPort=8080:socksPort=9089:hiddenServiceDir=/home/human/src/txtorcon/hidserv"

hs_endpoint = serverFromString(reactor, ep0)
txtorcon.IProgressProvider(hs_endpoint).add_progress_listener(progress)

# create our Web server and listen on the endpoint; this does the
# actual launching of (or connecting to) tor.
site = server.Site(Simple())
d = hs_endpoint.listen(site)
d.addCallback(setup_complete)
d.addErrback(setup_failed)

reactor.run()
