#!/usr/bin/env python

from twisted.web import server, resource, static
from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint, UNIXClientEndpoint

#from nevow import livepage

import txtorcon

torstate = None

def set_state(state):
    global torstate
    torstate = state

class Simple(resource.Resource):
    isLeaf = True

    def render_GET(self, request):
        global torstate
        if torstate is None:
            return "<html>No tor connection yet</html>"
        return "<html>Tor version <b>%s</b></html>" % torstate.protocol.version

    def getChild(self, path, resource):
        print "DING",path
        return static.File(path)

d = txtorcon.build_tor_connection(UNIXClientEndpoint(reactor, "/var/run/tor/control"))
d.addCallback(set_state)

site = server.Site(Simple())
reactor.listenTCP(8080, site)
reactor.run()
