from __future__ import print_function

# Here we set up a Twisted Web server and then launch our own tor with
# a configured hidden service directed at the Web server we set
# up. This uses serverFromString to translate the "onion" endpoint
# descriptor into a TCPHiddenServiceEndpoint object...

from twisted.web import server, resource
from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import react, deferLater
from twisted.internet.endpoints import serverFromString

import txtorcon


class Simple(resource.Resource):
    """
    A really simple Web site.
    """
    isLeaf = True

    def render_GET(self, request):
        return "<html>Hello, world! I'm a hidden service!</html>"


@inlineCallbacks
def main(reactor):
    # several ways to proceed here and what they mean:
    #
    # ep0:
    #    launch a new Tor instance, configure a hidden service on some
    #    port and pubish descriptor for port 80
    # ep1:
    #    connect to existing Tor via control-port 9051, configure a hidden
    #    service listening locally on 8080, publish a descriptor for port
    #    80 and use an explicit hiddenServiceDir (where "hostname" and
    #    "private_key" files are put by Tor). We set SOCKS port
    #    explicitly, too.
    # ep2:
    #    all the same as ep1, except we launch a new Tor (because no
    #    "controlPort=9051")
    #

    ep0 = "onion:80"
    ep1 = "onion:80:controlPort=9051:localPort=8080:socksPort=9089:hiddenServiceDir=/home/human/src/txtorcon/hidserv"
    ep2 = "onion:80:localPort=8080:socksPort=9089:hiddenServiceDir=/home/human/src/txtorcon/hidserv"
    hs_endpoint = serverFromString(reactor, ep0)

    def progress(percent, tag, message):
        bar = int(percent / 10)
        print("[{}{}] {}".format("#" * bar, "." * (10 - bar), message))
    txtorcon.IProgressProvider(hs_endpoint).add_progress_listener(progress)

    # create our Web server and listen on the endpoint; this does the
    # actual launching of (or connecting to) tor.
    site = server.Site(Simple())
    port = yield hs_endpoint.listen(site)

    # the port we get back will implement this (as well as IListeningPort)
    port = txtorcon.IHiddenService(port)
    print(
        "I have set up a hidden service, advertised at:\n"
        "http://{host}:{port}\n"
        "locally listening on {local_port}\n"
        "Will stop in 60 seconds...".format(
            host=port.getHost().onion_uri,
            port=port.getHost().onion_port,
            local_port=port.local_address.getHost(),
        )
    )

    def sleep(s):
        return deferLater(reactor, s, lambda: None)

    yield sleep(50)
    for i in range(10):
        print("Stopping in {}...".format(10 - i))
        yield sleep(1)
react(main)
