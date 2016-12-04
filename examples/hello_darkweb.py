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
from twisted.internet import endpoints, defer
from twisted.internet.task import react
from twisted.web import server, static, resource
import txtorcon


@defer.inlineCallbacks
def main(reactor):
    root = resource.Resource()
    root.putChild('', static.Data(
        "<html>Hello, hidden-service world!</html>",
        'text/html')
    )
    ep = endpoints.serverFromString(reactor, "onion:80")
    txtorcon.IProgressProvider(ep).add_progress_listener(
        lambda percent, tag, msg: print(msg)
    )
    port = yield ep.listen(server.Site(root))
    print("Our address {}".format(port))
    yield defer.Deferred()  # wait forever; this Deferred never fires
react(main)
