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
from twisted.internet import reactor, endpoints
from twisted.web import server, static
import txtorcon

res = static.Data("<html>Hello, hidden-service world!</html>", 'text/html')
ep = endpoints.serverFromString(reactor, "onion:80")
txtorcon.IProgressProvider(ep).add_progress_listener(lambda p, tag, msg: print(msg))
ep.listen(server.Site(res)).addCallback(lambda port: print(str(port.getHost()))).addErrback(print)

reactor.run()
