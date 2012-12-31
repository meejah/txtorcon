#!/usr/bin/env python

##
## Here we set up a Twisted Web server and then launch a slave tor
## with a configured hidden service directed at the Web server we set
## up. This uses TCPHiddenServiceEndpoint, which gives you slightly
## less control over how things are set up, but may be easier. See
## also the :ref:`launch_tor.py` example.
##

import tempfile
import functools

from twisted.internet import reactor

import txtorcon

def setup_failed(arg):
    print "SETUP FAILED",arg
    reactor.stop()

from twisted.web import server, resource
class Simple(resource.Resource):
    isLeaf = True
    def render_GET(self, request):
        return "<html>Hello, world! I'm a hidden service!</html>"
site = server.Site(Simple())

def setup_complete(port):
    print "I have set up a hidden service, advertised at:"
    print "http://%s:%d" % (port.onion_uri, port.onion_port)
    print "locally listening on",port.getHost()

def setup_hidden_service(tor_process_protocol):
    config = txtorcon.TorConfig(tor_process_protocol.tor_protocol)
    public_port = 80
    hs_endpoint = txtorcon.TCPHiddenServiceEndpoint(reactor, config, public_port)

    ## the important thing here is that "site" implements
    ## IProtocolFactory -- this could be any service at all,
    ## obviously.
    hs_endpoint.listen(site).addCallback(setup_complete).addErrback(setup_failed)

def updates(prog, tag, summary):
    print "%d%%: %s" % (prog, summary)

d = txtorcon.launch_tor(txtorcon.TorConfig(), reactor, progress_updates=updates)
d.addCallback(setup_hidden_service)
d.addErrback(setup_failed)
reactor.run()
