#!/usr/bin/env python

# This shows how to leverage the endpoints API to get a new hidden
# service up and running quickly. You can pass along this API to your
# users by accepting endpoint strings as per Twisted recommendations.
#
# http://twistedmatrix.com/documents/current/core/howto/endpoints.html#maximizing-the-return-on-your-endpoint-investment
#
# note that only the progress-updates needs the "import txtorcon" --
# you do still need it installed so that Twisted finds the endpoint
# parser plugin but code without knowledge of txtorcon can still
# launch a Tor instance using it. cool!

from __future__ import print_function
from twisted.internet import defer, task, endpoints
from twisted.web import server, static, resource
import txtorcon


@defer.inlineCallbacks
def main(reactor):
    # a simple Web site; could be any other listening service of course
    res = resource.Resource()
    res.putChild('/', static.Data("<html>Hello, onion-service world!</html>", 'text/html'))

    # "onion:" is for Tor Onion Services, and the only required
    # argument is the public port we advertise. You can pass
    # "controlPort=9051" for example, to connect to a system Tor
    # (accepts paths, too, e.g. "controlPort=/var/run/tor/control")
    ep = endpoints.serverFromString(reactor, "onion:80:controlPort=9151")
    #ep = endpoints.serverFromString(reactor, "onion:80")

    def on_progress(percent, tag, msg):
        print('%03d: %s' % (percent, msg))
    txtorcon.IProgressProvider(ep).add_progress_listener(on_progress)
    print("Note: descriptor upload can take several minutes")

    port = yield ep.listen(server.Site(res))
    print("Site listening: {}".format(port.getHost()))
    print("Private key:\n{}".format(port.getHost().onion_key))
    yield defer.Deferred()  # wait forever
task.react(main)
