# in-progress; implementing SOCKS5 client-side stuff as extended by
# tor because txsocksx will not be getting Python3 support any time
# soon, and its underlying dependency (Parsely) also doesn't support
# Python3. Also, Tor's SOCKS5 implementation is especially simple,
# since it doesn't do BIND or UDP ASSOCIATE.

from __future__ import print_function

import struct
from socket import inet_aton, inet_ntoa
from ipaddress import ip_address

from twisted.internet.defer import inlineCallbacks, returnValue, Deferred
from twisted.internet.interfaces import IProtocolFactory
from twisted.internet.protocol import Protocol, Factory
from twisted.internet.address import IPv4Address
from twisted.protocols import portforward
from twisted.protocols import tls
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.interfaces import IStreamClientEndpoint
from zope.interface import implementer

from txtorcon.spaghetti import FSM, State, Transition



@inlineCallbacks
def resolve(tor_endpoint, hostname):
    done = Deferred()
    factory = Factory.forProtocol(
        lambda: _TorSocksProtocol(done, hostname, 0, 'RESOLVE', None, None)
    )
    proto = yield tor_endpoint.connect(factory)
    result = yield done
    returnValue(result)


@inlineCallbacks
def resolve_ptr(tor_endpoint, hostname):
    done = Deferred()
    factory = Factory.forProtocol(
        lambda: _TorSocksProtocol(done, hostname, 0, 'RESOLVE_PTR', None, None)
    )
    proto = yield tor_endpoint.connect(factory)
    result = yield done
    returnValue(result)


@implementer(IStreamClientEndpoint)
class TorSocksEndpoint(object):
    """
    Represents a endpoint which will talk to a Tor SOCKS port. These
    should usually not be instantiated directly, instead use
    :meth:`txtorcon.TorConfig.socks_endpoint`.
    """
    def __init__(self, socks_endpoint, host, port, tls=False, got_source_port=None):
        self._proxy_ep = socks_endpoint  # can be Deferred
        self._host = host
        self._port = port
        self._tls = tls
        self._got_source_port = got_source_port

    @inlineCallbacks
    def connect(self, factory):
        done = Deferred()
        # further wrap the protocol if we're doing TLS.
        # "pray i do not wrap it further".
        if self._tls:
            # XXX requires Twisted 14+
            from twisted.internet.ssl import optionsForClientTLS
            context = optionsForClientTLS(unicode(self._host))
            tls_factory = tls.TLSMemoryBIOFactory(context, True, factory)
            socks_factory = Factory.forProtocol(
                lambda: _TorSocksProtocol(done, self._host, self._port, 'CONNECT', tls_factory, self._got_source_port)
            )
        else:
            socks_factory = Factory.forProtocol(
                lambda: _TorSocksProtocol(done, self._host, self._port, 'CONNECT', factory, self._got_source_port)
            )

        if isinstance(self._proxy_ep, Deferred):
            proxy_ep = yield self._proxy_ep
        else:
            proxy_ep = self._proxy_ep

        socks_proto = yield proxy_ep.connect(socks_factory)
        wrapped_proto = yield done
        if self._tls:
            returnValue(wrapped_proto.wrappedProtocol)
        else:
            returnValue(wrapped_proto)


class _TorSocksProtocol(Protocol):
    error_code_to_string = {
        0x00: 'succeeded',
        0x01: 'general SOCKS server failure',
        0x02: 'connection not allowed by ruleset',
        0x03: 'Network unreachable',
        0x04: 'Host unreachable',
        0x05: 'Connection refused',
        0x06: 'TTL expired',
        0x07: 'Command not supported',
        0x08: 'Address type not supported',
    }

    def __init__(self, done, host, port, socks_method, factory, got_source_port):
        """
        Private implementation detail -- do not instantiate directly. Use
        one of: resolve(), resolve_ptr() or TorSocksEndpoint

        :param done: a Deferred that will be callback()d with the
            address requested for RESOLVE or RESOLVE_PTR, or for the
            underlying (wrapped) protocol if the request was CONNECT.
        """
        self._done = done
        self._host = host[:255]
        self._port = port
        self._got_source_port = got_source_port
        assert port == int(port)
        assert port >= 0 and port < 2 ** 16
        self._auth_method = 0x02  # "USERNAME/PASSWORD"
        methods = {
            'CONNECT':     0x01,
            'RESOLVE':     0xf0,
            'RESOLVE_PTR': 0xf1,
        }
        assert socks_method in methods
        self._socks_method = methods[socks_method]
        self._factory = factory
        if self._socks_method == 0x01:
            self._done.addCallback(self._make_connection)
            if not self._factory:
                raise RuntimeError("factory required for CONNECT")
        else:
            if self._factory:
                raise RuntimeError("factory not allowed for RESOLVE/RESOLVE_PTR")

        self._sender = None
        self._sent_version_state = sent_version = State("SENT_VERSION")
        sent_request = State("SENT_REQUEST")
        relaying = State("RELAY_DATA")
        complete = State("DONE")
        error = State("ERROR")
        sent_version.add_transitions([
            Transition(sent_request, self._is_valid_version, self._send_socks_request),
            Transition(error, lambda msg: not self._is_valid_version(msg), self._error),
        ])
        sent_request.add_transitions([
            Transition(relaying, self._is_valid_response, self._parse_response),
            Transition(error, lambda msg: not self._is_valid_response(msg), self._error),
        ])
        relaying.add_transitions([
            Transition(relaying, None, self._relay_data),
        ])
        self._fsm = FSM([sent_version, sent_request, relaying, complete, error])

    @inlineCallbacks
    def _make_connection(self, _):
        # print("make connection!")
        addr = IPv4Address('TCP', self._reply_addr, self._reply_port)
        sender = yield self._factory.buildProtocol(addr)
        # portforward.ProxyClient is going to call setPeer but this
        # probably doesn't have it...
        client_proxy = portforward.ProxyClient()
        sender.makeConnection(self.transport)

        setattr(sender, 'setPeer', lambda _: None)
        client_proxy.setPeer(sender)
        self._sender = sender
        returnValue(sender)


    def _error(self, msg):
        reply = struct.unpack('B', msg[1:2])[0]
        print("error; aborting SOCKS:", self.error_code_to_string[reply])
        self.transport.loseConnection()
        # connectionLost will errback on self._done

    def _relay_data(self, data):
        # print("relay {} bytes".format(len(data)))
        self._sender.dataReceived(data)

    def _is_valid_response(self, msg):
        # print("_is_valid_response", msg)
        try:
            (version, reply, _, typ) = struct.unpack('BBBB', msg[:4])
            return version == 5 and reply == 0 and typ in [0x01, 0x03, 0x04]
        except Exception as e:
            print("txtorcon internal error", e)
            return False

    def _parse_response(self, msg):
        (version, reply, _, typ) = struct.unpack('BBBB', msg[:4])
        if typ == 0x01: # IPv4
            addr = inet_ntoa(msg[4:8])
        elif typ == 0x03:  # DOMAINNAME
            addrlen = struct.unpack('B', msg[4:5])[0]
            addr = msg[5:5 + addrlen]
        elif typ == 0x04:  # IPv6
            addr = msg[4:20]
        else:
            raise Exception("logic error")
        port = struct.unpack('H', msg[-2:])[0]
        self._reply_addr = addr
        self._reply_port = port
        # print("reply {} {}".format(addr, port))
        if self._socks_method in [0xf0, 0xf1]:
            self._done.callback(addr)
            self.transport.loseConnection()
            return self._sent_version_state
        else:  # CONNECT
            # XXX probably we could receive some early bytes? if we
            # have more than the expected bytes, should
            # self._relay_data() them here...
            self._done.callback(None)
            # _done will actually callback with 'sender' from
            # self._make_connection()

    def _is_valid_version(self, msg):
        # print("_is_valid_version", msg)
        try:
            (version, method) = struct.unpack('BB', msg)
            return version == 5 and method in [0x00, 0x02]
        except Exception:
            return False

    def _send_socks_request(self, msg):
        # https://gitweb.torproject.org/torspec.git/tree/socks-extensions.txt
        # CMD is one of:
        # - 0x1 CONNECT
        # - 0xF0 for RESOLVE (see above)
        # - 0xF1 for RESOLVE_PTR (see above)
        # SOCKS methods 0x02 BIND and 0x03 UDP ASSOCIATE are *not*
        # supported (by tor, nor us)

        # XXX probably "state machine" itself here; could split
        # SENT_REQUEST to 2 states?
        if self._socks_method == 0xf1:
            data = struct.pack(
                '!BBBB4sH',
                5,                  # version
                self._socks_method, # command
                0x00,               # reserved
                0x01,               # IPv4 address
                inet_aton(self._host),
                self._port,
            )
        else:
            data = struct.pack(
                '!BBBBB{}sH'.format(len(self._host)),
                5,                  # version
                self._socks_method, # command
                0x00,               # reserved
                0x03,               # DOMAINNAME
                len(self._host),
                self._host,
                self._port,
            )
        self.transport.write(data)


    def connectionMade(self):
        # print("connectionMade", self.transport.getHost())
        if self._got_source_port:
            self._got_source_port.callback(self.transport.getHost())
        self._fsm.state = self._fsm.states[0]  # SENT_VERSION
        # ask for 2 methods: 0 (anonymous) and 2 (authenticated)
        data = struct.pack('BBBB', 5, 2, 0, 2)
        # ask for 1 methods: 0 (anonymous)
        data = struct.pack('BBB', 5, 1, 0)
        self.transport.write(data)

    def connectionLost(self, reason):
        # print("connectionLost", reason)
        if self._sender:
            self._sender.connectionLost(reason)
        if not self._done.called:
            self._done.callback(reason)

    def dataReceived(self, d):
        # print("dataReceived({} bytes)".format(len(d)))
        self._fsm.process(d)
        return
