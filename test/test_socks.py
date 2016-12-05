
from mock import Mock

from twisted.trial import unittest
from twisted.internet import defer
from twisted.test import proto_helpers
from twisted.internet.address import IPv4Address

from txtorcon import socks


# XXX should re-write (at LEAST) these to use Twisted's IOPump
class SocksConnectTests(unittest.TestCase):

    @defer.inlineCallbacks
    def test_connect_no_tls(self):
        socks_ep = Mock()
        transport = proto_helpers.StringTransport()

        def connect(factory):
            factory.startFactory()
            proto = factory.buildProtocol("addr")
            proto.makeConnection(transport)
            self.assertEqual(b'\x05\x01\x00', transport.value())
            proto.dataReceived(b'\x05\x00')
            proto.dataReceived(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            return proto
        socks_ep.connect = connect
        protocol = Mock()
        factory = Mock()
        factory.buildProtocol = Mock(return_value=protocol)
        ep = socks.TorSocksEndpoint(socks_ep, b'meejah.ca', 443)
        proto = yield ep.connect(factory)
        self.assertEqual(proto, protocol)

    @defer.inlineCallbacks
    def test_connect_deferred_proxy(self):
        socks_ep = Mock()
        transport = proto_helpers.StringTransport()

        def connect(factory):
            factory.startFactory()
            proto = factory.buildProtocol("addr")
            proto.makeConnection(transport)
            self.assertEqual(b'\x05\x01\x00', transport.value())
            proto.dataReceived(b'\x05\x00')
            proto.dataReceived(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            return proto
        socks_ep.connect = connect
        protocol = Mock()
        factory = Mock()
        factory.buildProtocol = Mock(return_value=protocol)
        ep = socks.TorSocksEndpoint(
            socks_endpoint=defer.succeed(socks_ep),
            host=b'meejah.ca',
            port=443,
        )
        proto = yield ep.connect(factory)
        self.assertEqual(proto, protocol)

    @defer.inlineCallbacks
    def test_connect_tls(self):
        socks_ep = Mock()
        transport = proto_helpers.StringTransport()

        def connect(factory):
            factory.startFactory()
            proto = factory.buildProtocol("addr")
            proto.makeConnection(transport)
            self.assertEqual(b'\x05\x01\x00', transport.value())
            proto.dataReceived(b'\x05\x00')
            proto.dataReceived(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            return proto
        socks_ep.connect = connect
        protocol = Mock()
        factory = Mock()
        factory.buildProtocol = Mock(return_value=protocol)
        ep = socks.TorSocksEndpoint(socks_ep, b'meejah.ca', 443, tls=True)
        proto = yield ep.connect(factory)
        self.assertEqual(proto, protocol)

    @defer.inlineCallbacks
    def test_connect_socks_error(self):
        socks_ep = Mock()
        transport = proto_helpers.StringTransport()

        def connect(factory):
            factory.startFactory()
            proto = factory.buildProtocol("addr")
            proto.makeConnection(transport)
            self.assertEqual(b'\x05\x01\x00', transport.value())
            proto.dataReceived(b'\x05\x01')
            #proto.dataReceived(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            #proto.dataReceived(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            return proto
        socks_ep.connect = connect
        protocol = Mock()
        factory = Mock()
        factory.buildProtocol = Mock(return_value=protocol)
        ep = socks.TorSocksEndpoint(socks_ep, b'meejah.ca', 443, tls=True)
        with self.assertRaises(Exception) as ctx:
            yield ep.connect(factory)
        self.assertTrue('general SOCKS server failure' in str(ctx.exception))

    @defer.inlineCallbacks
    def test_get_address_endpoint(self):
        socks_ep = Mock()
        transport = proto_helpers.StringTransport()

        def connect(factory):
            factory.startFactory()
            proto = factory.buildProtocol("addr")
            proto.makeConnection(transport)
            self.assertEqual(b'\x05\x01\x00', transport.value())
            proto.dataReceived(b'\x05\x00')
            proto.dataReceived(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            return proto
        socks_ep.connect = connect
        protocol = Mock()
        factory = Mock()
        factory.buildProtocol = Mock(return_value=protocol)
        ep = socks.TorSocksEndpoint(socks_ep, b'meejah.ca', 443, tls=True)
        with self.assertRaises(RuntimeError) as ctx:
            yield ep.get_address()
        proto = yield ep.connect(factory)
        addr = yield ep.get_address()

        self.assertEqual(addr, IPv4Address('TCP', '10.0.0.1', 12345))
        self.assertTrue('call .connect()' in str(ctx.exception))

    @defer.inlineCallbacks
    def test_get_address(self):
        # normally, .get_address is only called via the
        # attach_stream() method on Circuit
        addr = object()
        factory = socks._TorSocksFactory()
        d = factory.get_address()
        self.assertFalse(d.called)
        factory._did_connect(addr)

        maybe_addr = yield d

        self.assertEqual(addr, maybe_addr)

        # if we do it a second time, should be immediate
        d = factory.get_address()
        self.assertTrue(d.called)
        self.assertEqual(d.result, addr)


class SocksResolveTests(unittest.TestCase):

    @defer.inlineCallbacks
    def test_resolve(self):
        socks_ep = Mock()
        transport = proto_helpers.StringTransport()

        def connect(factory):
            factory.startFactory()
            proto = factory.buildProtocol("addr")
            proto.makeConnection(transport)
            # XXX sadness: we probably "should" just feed the right
            # bytes to the protocol to convince it a connection is
            # made ... *or* we can cheat and just do the callback
            # directly...
            proto._done.callback("the dns answer")
            return proto
        socks_ep.connect = connect
        hn = yield socks.resolve(socks_ep, b'meejah.ca')
        self.assertEqual(hn, "the dns answer")

    @defer.inlineCallbacks
    def test_resolve_ptr(self):
        socks_ep = Mock()
        transport = proto_helpers.StringTransport()

        def connect(factory):
            factory.startFactory()
            proto = factory.buildProtocol("addr")
            proto.makeConnection(transport)
            # XXX sadness: we probably "should" just feed the right
            # bytes to the protocol to convince it a connection is
            # made ... *or* we can cheat and just do the callback
            # directly...
            proto._done.callback("the dns answer")
            return proto
        socks_ep.connect = connect
        hn = yield socks.resolve_ptr(socks_ep, b'meejah.ca')
        self.assertEqual(hn, "the dns answer")
