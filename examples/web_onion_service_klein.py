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
import sys

from twisted.internet import defer, task, endpoints
from twisted.web import server

import txtorcon
from txtorcon.util import default_control_port

try:
    from klein import Klein
except ImportError:
    print("To use this example, you must install Klein:")
    print("   pip install klein")
    sys.exit(1)


app = Klein()


@app.route('/')
def home(request):
    return 'Hello from Klein, Onion World'


@defer.inlineCallbacks
def main(reactor):
    ep = endpoints.serverFromString(reactor, "onion:80:controlPort={port}".format(port=default_control_port()))

    def on_progress(percent, tag, msg):
        print('%03d: %s' % (percent, msg))
    txtorcon.IProgressProvider(ep).add_progress_listener(on_progress)
    print("Note: descriptor upload can take several minutes")

    port = yield ep.listen(server.Site(app.resource()))
    print("Site listening: {}".format(port.getHost()))
    print("Private key:\n{}".format(port.getHost().onion_key))
    print("\nVisit using Tor Browser: http://{}\n".format(port.getHost().onion_uri))
    yield defer.Deferred()  # wait forever


if __name__ == '__main__':
    task.react(main)
