#!/usr/bin/env python

from __future__ import print_function
from twisted.internet import defer, task, endpoints
from twisted.web import server, static, resource

import txtorcon
from txtorcon.util import default_control_port


@defer.inlineCallbacks
def main(reactor):
    # a simple Web site; could be any other listening service of course
    res = resource.Resource()
    res.putChild(b'', static.Data("<html>Hello, onion-service world!</html>", 'text/html'))

    # if we don't provide a control-endpoint, this will try some default ones
    tor = yield txtorcon.connect(reactor)

    # an endpoint that'll listen on port 80, and put the hostname +
    # private_key files in './hidden_service_dir'
    hs_dir = './hidden_service_dir'
    print("Creating hidden-service, keys in: {}".format(hs_dir))
    ep = tor.create_onion_disk_endpoint(80, hs_dir=hs_dir)

    print("Note: descriptor upload can take several minutes")

    def on_progress(percent, tag, msg):
        print('%03d: %s' % (percent, msg))
    txtorcon.IProgressProvider(ep).add_progress_listener(on_progress)

    port = yield ep.listen(server.Site(res))
    print("Private key:\n{}".format(port.getHost().onion_key))
    print("Site listening: {}".format(port.getHost()))
    yield defer.Deferred()  # wait forever

if __name__ == '__main__':
    task.react(main)
