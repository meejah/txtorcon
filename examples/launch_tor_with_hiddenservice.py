#!/usr/bin/env python

# Here we set up a Twisted Web server and then launch a slave tor
# with a configured hidden service directed at the Web server we set
# up.

import tempfile
import functools

from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.web import server, resource

import txtorcon


class Simple(resource.Resource):
    isLeaf = True

    def render_GET(self, request):
        return "<html>Hello, world! I'm a hidden service!</html>"


def updates(prog, tag, summary):
    print "%d%%: %s" % (prog, summary)


def setup_complete(config, proto):
    print "Protocol completed"

    onion_address = config.HiddenServices[0].hostname

    print "I have a hidden (web) service running at:"
    print "http://%s (port %d)" % (onion_address, hs_public_port)
    print "The temporary directory for it is at:", config.HiddenServices[0].dir
    print
    print "For example, you should be able to visit it via:"
    print "  torsocks lynx http://%s" % onion_address


def setup_failed(arg):
    print "SETUP FAILED", arg
    reactor.stop()

hs_port = 9876
hs_public_port = 80
hs_temp = tempfile.mkdtemp(prefix='torhiddenservice')

# register something to clean up our tempdir
reactor.addSystemEventTrigger(
    'before', 'shutdown',
    functools.partial(
        txtorcon.util.delete_file_or_tree,
        hs_temp
    )
)

# configure the hidden service we want.
# obviously, we'd want a more-persistent place to keep the hidden
# service directory for a "real" setup. If the directory is empty at
# startup as here, Tor creates new keys etcetera (which IS the .onion
# address). That is, every time you run this script you get a new
# hidden service URI, which is probably not what you want.
# The launch_tor method adds other needed config directives to give
# us a minimal config.
config = txtorcon.TorConfig()
config.SOCKSPort = 0
config.ORPort = 9089
config.HiddenServices = [
    txtorcon.HiddenService(
        config,
        hs_temp,
        ["%d 127.0.0.1:%d" % (hs_public_port, hs_port)]
    )
]
config.save()

# next we set up our service to listen on hs_port which is forwarded
# (via the HiddenService options) from the hidden service address on
# port hs_public_port
site = server.Site(Simple())
hs_endpoint = TCP4ServerEndpoint(reactor, hs_port, interface='127.0.0.1')
hs_endpoint.listen(site)

# we've got our Twisted service listening locally and our options
# ready to go, so we now launch Tor. Once it's done (see above
# callbacks) we print out the .onion URI and then do "nothing"
# (i.e. let the Web server do its thing). Note that the way we've set
# up the slave Tor process, when we close the connection to it tor
# will exit.

d = txtorcon.launch_tor(config, reactor, progress_updates=updates)
d.addCallback(functools.partial(setup_complete, config))
d.addErrback(setup_failed)
reactor.run()
