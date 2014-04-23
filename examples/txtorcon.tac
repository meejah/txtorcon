import functools
from os.path import dirname
import sys
from tempfile import mkdtemp

import txtorcon

from twisted.application import service, internet
from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.python import log
from twisted.web import static, server
from zope.interface import implements


class TorService(service.Service):
    implements(service.IService)
    directory = dirname(__file__)
    port = 8080

    def __init__(self):
        self.torfactory = txtorcon.TorProtocolFactory()
        self.connection = TCP4ClientEndpoint(reactor, 'localhost', 9052)
        self.resource = server.Site(static.File(self.directory))

    def startService(self):
        service.Service.startService(self)

        reactor.listenTCP(self.port, self.resource)
        self._bootstrap().addCallback(self._complete)

    def _bootstrap(self):
        self.config = txtorcon.TorConfig()
        self.config.HiddenServices = [
            txtorcon.HiddenService(self.config, mkdtemp(),
                                   ['%d 127.0.0.1:%d' % (80, self.port)])
        ]
        self.config.save()
        return txtorcon.launch_tor(self.config, reactor,
                                   progress_updates=self._updates,
                                   tor_binary='tor')

    def _updates(self, prog, tag, summary):
        log.msg('%d%%: %s' % (prog, summary))

    def _complete(self, proto):
        log.msg(self.config.HiddenServices[0].hostname)

application = service.Application("Txtorcon Application")
torservice = TorService()
torservice.setServiceParent(application)
