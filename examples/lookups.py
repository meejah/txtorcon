from __future__ import print_function

from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks
from twisted.internet.endpoints import clientFromString
import txtorcon
from txtorcon import socks

@inlineCallbacks
def main(reactor):
    tor_ep = clientFromString(reactor, "tcp:localhost:9050")
    for domain in [u'www.torproject.org', u'meejah.ca']:
        print("Looking up '{}' via Tor".format(domain))
        ans = yield socks.resolve(tor_ep, domain)
        print("...got answer: {}".format(ans))
        print("Doing PTR on {}".format(ans))
        ans = yield socks.resolve_ptr(tor_ep, ans)
        print("...got answer: {}".format(ans))


if __name__ == '__main__':
    react(main)
