from __future__ import print_function

from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks
from twisted.internet.endpoints import clientFromString
import txtorcon


@inlineCallbacks
def main(reactor):
    tor = yield txtorcon.connect(reactor, clientFromString(reactor, "tcp:localhost:9051"))
    for domain in ['torproject.org', 'meejah.ca']:
        print("Looking up '{}' via Tor".format(domain))
        ans = yield tor.dns_resolve(domain)
        print("...got answer: {}".format(ans))
        print("Doing PTR on {}".format(ans))
        ans = yield tor.dns_resolve_ptr(ans)
        print("...got answer: {}".format(ans))

if __name__ == '__main__':
    react(main)
