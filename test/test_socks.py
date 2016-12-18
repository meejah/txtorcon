from StringIO import StringIO
from mock import Mock

from twisted.trial import unittest
from twisted.internet import defer
from twisted.internet.address import IPv4Address
from twisted.internet.protocol import Protocol
from twisted.test import proto_helpers

from txtorcon import socks

class SocksStateMachine(unittest.TestCase):

    def test_illegal_request(self):
        with self.assertRaises(ValueError) as ctx:
            socks.SocksMachine('FOO_RESOLVE', 'meejah.ca', 443)
        self.assertTrue(
            'Unknown request type' in str(ctx.exception)
        )

    def test_dump_graphviz(self):
        with open('socks.dot', 'w') as f:
            for line in socks.SocksMachine._machine.graphviz():
                f.write(line)

    @defer.inlineCallbacks
    def test_connect_socks_illegal_packet(self):
        from twisted.test.iosim import IOPump, connect, FakeTransport

        class BadSocksServer(Protocol):
            def __init__(self):
                self._buffer = b''

            def dataReceived(self, data):
                print("BADSOCKS got data", data)
                self._buffer += data
                if len(self._buffer) == 3:
                    assert self._buffer == b'\x05\x01\x00'
                    self._buffer = b''
                    self.transport.write(b'\x05\x01\x01')

        done = defer.Deferred()
        factory = socks._TorSocksFactory2(b'meejah.ca', 1234, 'CONNECT', Mock())
        server_proto = BadSocksServer()
        server_transport = FakeTransport(server_proto, isServer=True)

        client_proto = factory.buildProtocol('ignored')
        client_transport = FakeTransport(client_proto, isServer=False)

        pump = yield connect(
            server_proto, server_transport,
            client_proto, client_transport,
        )

        self.assertTrue(server_proto.transport.disconnected)
        self.assertTrue(client_proto.transport.disconnected)

    def test_end_to_end_wrong_method(self):

        dis = []
        def on_disconnect(error_message):
            dis.append(error_message)
        sm = socks.SocksMachine('RESOLVE', 'meejah.ca', 443, on_disconnect)
        sm.connection()

        sm.feed_data('\x05')
        sm.feed_data('\x01')

        # we should have sent the request to the server, and nothing
        # else (because we disconnected)
        data = StringIO()
        sm.send_data(data.write)
        self.assertEqual(
            '\x05\x01\x00',
            data.getvalue(),
        )
        self.assertEqual(1, len(dis))
        self.assertEqual("Wanted method 0 or 2, got 1", dis[0])

    def test_end_to_end_wrong_version(self):

        dis = []
        def on_disconnect(error_message):
            dis.append(error_message)
        sm = socks.SocksMachine('RESOLVE', 'meejah.ca', 443, on_disconnect)
        sm.connection()

        sm.feed_data('\x06')
        sm.feed_data('\x00')

        # we should have sent the request to the server, and nothing
        # else (because we disconnected)
        data = StringIO()
        sm.send_data(data.write)
        self.assertEqual(
            '\x05\x01\x00',
            data.getvalue(),
        )
        self.assertEqual(1, len(dis))
        self.assertEqual("Expected version 5, got 6", dis[0])

    def test_end_to_end_connection_refused(self):

        dis = []
        def on_disconnect(error_message):
            dis.append(error_message)
        sm = socks.SocksMachine('CONNECT', '1.2.3.4', 443, on_disconnect)
        sm.connection()

        sm.feed_data('\x05')
        sm.feed_data('\x00')

        # reply with 'connection refused'
        sm.feed_data('\x05\x05\x00\x01\x00\x00\x00\x00\xff\xff')

        self.assertEqual(1, len(dis))
        self.assertEqual("Connection refused", dis[0])

    def test_end_to_end_successful_relay(self):

        dis = []
        def on_disconnect(error_message):
            dis.append(error_message)
        sm = socks.SocksMachine('CONNECT', '1.2.3.4', 443, on_disconnect)
        sm.connection()

        sm.feed_data('\x05')
        sm.feed_data('\x00')

        # reply with success, port 0x1234
        sm.feed_data('\x05\x00\x00\x01\x00\x00\x00\x00\x12\x34')

        # now some data that should get relayed
        sm.feed_data('this is some relayed data')
        # should *not* have disconnected
        self.assertEqual(0, len(dis))
        data = StringIO()
        sm.send_data(data.write)
        self.assertTrue(data.getvalue().endswith("this is some relayed data"))

    def test_end_to_end_success(self):
        sm = socks.SocksMachine('RESOLVE', 'meejah.ca', 443)
        sm.connection()

        sm.feed_data('\x05')
        sm.feed_data('\x00')

        # now we check we got the right bytes out the other side
        data = StringIO()
        sm.send_data(data.write)
        self.assertEqual(
            '\x05\x01\x00'
            '\x05\xf0\x00\x03\tmeejah.ca\x00\x00',
            data.getvalue(),
        )

    def test_end_to_end_connect_and_relay(self):
        sm = socks.SocksMachine('CONNECT', '1.2.3.4', 443)
        sm.connection()

        sm.feed_data('\x05')
        sm.feed_data('\x00')
        sm.feed_data('some relayed data')

        # now we check we got the right bytes out the other side
        data = StringIO()
        sm.send_data(data.write)
        self.assertEqual(
            '\x05\x01\x00'
            '\x05\x01\x00\x01\x01\x02\x03\x04\x01\xbb',
            data.getvalue(),
        )

    def test_resolve(self):
        sm = socks.SocksMachine('RESOLVE', 'meejah.ca', 443)
        sm.connection()
        sm.version_reply(0x02)

        data = StringIO()
        sm.send_data(data.write)
        self.assertEqual(
            '\x05\x01\x00'
            '\x05\xf0\x00\x03\tmeejah.ca\x00\x00',
            data.getvalue(),
        )

    def test_resolve_ptr(self):
        sm = socks.SocksMachine('RESOLVE_PTR', '1.2.3.4', 443)
        sm.connection()
        sm.version_reply(0x00)

        data = StringIO()
        sm.send_data(data.write)
        self.assertEqual(
            '\x05\x01\x00'
            '\x05\xf1\x00\x03\x071.2.3.4\x00\x00',
            data.getvalue(),
        )

    def test_connect(self):
        sm = socks.SocksMachine('CONNECT', '1.2.3.4', 443)
        sm.connection()
        sm.version_reply(0x00)

        data = StringIO()
        sm.send_data(data.write)
        self.assertEqual(
            '\x05\x01\x00'
            '\x05\x01\x00\x01\x01\x02\x03\x04\x01\xbb',
            data.getvalue(),
        )


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
