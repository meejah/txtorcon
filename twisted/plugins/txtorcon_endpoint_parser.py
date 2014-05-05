#!/usr/bin/env python

from zope.interface import implementer
from twisted.plugin import IPlugin
from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from twisted.internet.interfaces import IStreamServerEndpointStringParser
from twisted.internet.endpoints import serverFromString

import txtorcon


@implementer(IPlugin, IStreamServerEndpointStringParser)
class TorHiddenServiceEndpointStringParser(object):
    prefix = "onion"

    def _parseServer(self, reactor, publicPort=None, localPort=None, controlPort=None, socksPort=None, hiddenServiceDir=None):

        assert publicPort is not None

        return txtorcon.TCPHiddenServiceEndpoint(reactor, publicPort=publicPort, localPort=localPort, controlPort=controlPort, socksPort=socksPort, hiddenServiceDir=hiddenServiceDir)

    def parseStreamServer(self, reactor, *args, **kwargs):
        return self._parseServer(reactor, *args, **kwargs)


torHiddenServiceEndpointStringParser = TorHiddenServiceEndpointStringParser()
