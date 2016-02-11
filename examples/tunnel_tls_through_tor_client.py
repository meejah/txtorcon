
from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.python.filepath import FilePath
from twisted.internet import ssl, task, protocol, endpoints, defer
from twisted.python.modules import getModule
from txsocksx.tls import TLSWrapClientEndpoint
import txtorcon

import other_proto


@defer.inlineCallbacks
def main(reactor):
    factory = protocol.Factory.forProtocol(other_proto.DecisionProtocol)
    ca_data = FilePath(b'ca_cert.pem').getContent()
    client_data = FilePath(b'a.client.pem').getContent()
    ca_cert = ssl.Certificate.loadPEM(ca_data)
    client_key = ssl.PrivateCertificate.loadPEM(client_data)
    options = ssl.optionsForClientTLS(u'the-authority', ca_cert, client_key)
    exampleEndpoint = txtorcon.TorClientEndpoint(ip, 8966, socks_hostname="127.0.0.1")
    tlsEndpoint = TLSWrapClientEndpoint(options, exampleEndpoint)
    deferred = yield tlsEndpoint.connect(factory)
    done = defer.Deferred()
    deferred.connectionLost = lambda reason: done.callback(None)
    yield done


task.react(main)
