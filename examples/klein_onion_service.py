#!/usr/bin/env python

# you must install "klein" to use this example. See:
# https://klein.readthedocs.org/en/latest/

from __future__ import print_function
from twisted.internet import defer, task, endpoints, reactor
from twisted.web import server, static
import txtorcon

from klein import Klein
app = Klein()

@app.route('/')
def home(request):
    return 'Hello, world!'


# have to bypass klein's app.run() as that doesn't take endpoints
site = server.Site(app.resource())


def main(reactor):
    ep = endpoints.serverFromString(reactor, "onion:80")

    def on_progress(percent, tag, msg):
        print('%03d: %s' % (percent, msg))
    txtorcon.IProgressProvider(ep).add_progress_listener(on_progress)

    def site_listening(port):
        print("Site listening: {}".format(port.getHost()))
    d = ep.listen(site)
    d.addCallback(site_listening)
    d.addCallback(lambda _: defer.Deferred())  # wait forever
    return d
task.react(main)
