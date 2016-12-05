#!/usr/bin/env python

from __future__ import print_function
from twisted.internet import defer, task
from twisted.web import server, static, resource

import txtorcon


@defer.inlineCallbacks
def main(reactor):
    # a simple Web site; could be any other listening service of course
    res = resource.Resource()
    res.putChild(
        b'',
        static.Data("<html>Hello, onion-service world!</html>", 'text/html')
    )

    def on_progress(percent, tag, msg):
        print('%03d: %s' % (percent, msg))

    # We are using launch() here instead of connect() because
    # filesystem services are very picky about the permissions and
    # ownership of the directories involved. If you *do* want to
    # connect to e.g. a system service or Tor Browser Bundle, it's way
    # more likely to work to use Ephemeral services

    tor = yield txtorcon.launch(reactor, progress_updates=on_progress)

    # an endpoint that'll listen on port 80, and put the hostname +
    # private_key files in './hidden_service_dir'

    # NOTE: you should put these somewhere you've thought about more
    # and made proper permissions for the parent directory, etc. A
    # good choice for a system-wide Tor is /var/lib/tor/<whatever>
    hs_dir = './hidden_service_dir'

    print("Creating hidden-service, keys in: {}".format(hs_dir))
    ep = tor.create_onion_disk_endpoint(80, hs_dir=hs_dir, group_readable=True)

    print("Note: descriptor upload can take several minutes")

    txtorcon.IProgressProvider(ep).add_progress_listener(on_progress)

    port = yield ep.listen(server.Site(res))
    print("Private key:\n{}".format(port.getHost().onion_key))
    print("Site listening: {}".format(port.getHost()))
    yield defer.Deferred()  # wait forever


if __name__ == '__main__':
    task.react(main)
