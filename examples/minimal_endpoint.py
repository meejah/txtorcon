#!/usr/bin/env python

from twisted.internet import reactor
from twisted.internet.endpoints import serverFromString
from twisted.web import server, static

serverFromString(reactor, "onion:80").listen(
    server.Site(static.Data("Hello, world!", "text/plain"))
).addCallback(print)
reactor.run()
