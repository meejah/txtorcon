# in-progress; implementing SOCKS5 client-side stuff as extended by
# tor because txsocksx will not be getting Python3 support any time
# soon, and its underlying dependency (Parsely) also doesn't support
# Python3. Also, Tor's SOCKS5 implementation is especially simple,
# since it doesn't do BIND or UDP ASSOCIATE.

from __future__ import print_function

import six
import struct
from socket import inet_aton, inet_ntoa
# from ipaddress import ip_address

from twisted.internet.defer import inlineCallbacks, returnValue, Deferred
from twisted.internet.protocol import Protocol, Factory
from twisted.internet.address import IPv4Address
from twisted.python.failure import Failure
from twisted.protocols import portforward
from twisted.protocols import tls
# from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.interfaces import IStreamClientEndpoint
from zope.interface import implementer

from txtorcon.spaghetti import FSM, State, Transition


# okay, so what i want to do to fix this crap up is:
# - state-machine is separate (doesn't do parsing)
# - parsing incoming data into symbols for the state-machine
# - (the parser sadly has to know the current state, because no SOCKS framing)
# - ideally also make it "IO neutral", i.e. so could be basis for a
#   synchronous SOCKS thing

# so, e.g. states ge



import automat

class SocksMachine(object):
    """
    trying to prototype the SOCKS state-machine in automat

    This is a SOCKS state machine to make a single request.
    """
    _machine = automat.MethodicalMachine()

    def __init__(self, req_type, host, port=0):
        self._outgoing_data = []
        if req_type not in self._dispatch:
            raise ValueError(
                "Unknown request type '{}'".format(req_type)
            )
        self._req_type = req_type
        self._host = host
        self._port = port

    def send_data(self, callback):
        while len(self._outgoing_data):
            data = self._outgoing_data.pop(0)
            callback(data)

    @_machine.input()
    def connected(self):
        "begin the protocol (i.e. connection made)"

    @_machine.input()
    def disconnected(self):
        "the connection has gone away"

    @_machine.input()
    def version_reply(self):
        "the SOCKS server replied with a version"

    @_machine.output()
    def _send_version(self):
        "sends a SOCKS version reply"
        self._outgoing_data.append(
            # for anonymous(0) *and* authenticated (2): struct.pack('BBBB', 5, 2, 0, 2)
            struct.pack('BBB', 5, 1, 0)
        )

    @_machine.output()
    def _send_request(self):
        "send the request (connect, resolve or resolve_ptr)"
        return self._dispatch[self._req_type](self)

    def _send_connect_request(self):
        "sends CONNECT request"
        self._outgoing_data.append(
            struct.pack(
                '!BBBB4sH',
                5,                   # version
                0x01,                # command
                0x00,                # reserved
                0x01,                # IPv4 address
                inet_aton(self._host),
                self._port,
            )
        )

    @_machine.output()
    def _send_resolve_request(self):
        "sends RESOLVE_PTR request (Tor custom)"
        self._outgoing_data.append(
            struct.pack(
                '!BBBBB{}sH'.format(len(self._host)),
                5,                   # version
                0xF0,                # command
                0x00,                # reserved
                0x03,                # DOMAINNAME
                len(self._host),
                self._host,
                0,  # self._port?
            )
        )

    @_machine.output()
    def _send_resolve_ptr_request(self):
        "sends RESOLVE_PTR request (Tor custom)"
        self._outgoing_data.append(
            struct.pack(
                '!BBBBB{}sH'.format(len(self._host)),
                5,                   # version
                0xF1,                # command
                0x00,                # reserved
                0x03,                # DOMAINNAME
                len(self._host),
                self._host,
                0,              # why do we specify port at all?
            )
        )

    @_machine.state(initial=True)
    def unconnected(self):
        "not yet connected"

    @_machine.state()
    def sent_version(self):
        "we've sent our version request"

    @_machine.state()
    def sent_request(self):
        "we've sent our stream/etc request"

    unconnected.upon(
        connected,
        enter=sent_version,
        outputs=[_send_version],
    )

    sent_version.upon(
        version_reply,
        enter=sent_request,
        outputs=[_send_request],
    )
    sent_version.upon(
        disconnected,
        enter=unconnected,
        outputs=[]
    )
    _dispatch = {
        'CONNECT': _send_connect_request,
        'RESOLVE': _send_resolve_request,
        'RESOLVE_PTR': _send_resolve_ptr_request,
    }



class SocksError(Exception):
    pass


@inlineCallbacks
def resolve(tor_endpoint, hostname):
    """
    This is easier to use via :meth:`txtorcon.Tor.dns_resolve`

    :param tor_endpoint: the Tor SOCKS endpoint to use.

    :param hostname: the hostname to look up.
    """
    done = Deferred()
    factory = _TorSocksFactory(
        done, hostname, 0, 'RESOLVE', None,
    )
    yield tor_endpoint.connect(factory)
    result = yield done
    returnValue(result)


@inlineCallbacks
def resolve_ptr(tor_endpoint, hostname):
    done = Deferred()
    factory = _TorSocksFactory(
        done, hostname, 0, 'RESOLVE_PTR', None,
    )
    yield tor_endpoint.connect(factory)
    result = yield done
    returnValue(result)


@implementer(IStreamClientEndpoint)
class TorSocksEndpoint(object):
    """
    Represents an endpoint which will talk to a Tor SOCKS port.

    These should usually not be instantiated directly, instead use
    :meth:`txtorcon.TorConfig.socks_endpoint`.
    """
    def __init__(self, socks_endpoint, host, port, tls=False):
        self._proxy_ep = socks_endpoint  # can be Deferred
        self._host = host
        self._port = port
        self._tls = tls
        self._socks_factory = None

    def get_address(self):
        """
        Returns a Deferred that fires with the source IAddress of the
        underlying SOCKS connection (i.e. usually a
        twisted.internet.address.IPv4Address)

        circuit.py uses this; better suggestions welcome!
        """
        if self._socks_factory is None:
            raise RuntimeError(
                "Have to call .connect() before calling .get_address()"
            )
        return self._socks_factory.get_address()

    @inlineCallbacks
    def connect(self, factory):
        done = Deferred()
        # further wrap the protocol if we're doing TLS.
        # "pray i do not wrap it further".
        if self._tls:
            # XXX requires Twisted 14+
            from twisted.internet.ssl import optionsForClientTLS
            context = optionsForClientTLS(self._host.decode())
            tls_factory = tls.TLSMemoryBIOFactory(context, True, factory)
            socks_factory = _TorSocksFactory(
                done, self._host, self._port, 'CONNECT', tls_factory,
            )
        else:
            socks_factory = _TorSocksFactory(
                done, self._host, self._port, 'CONNECT', factory,
            )

        self._socks_factory = socks_factory
        if isinstance(self._proxy_ep, Deferred):
            proxy_ep = yield self._proxy_ep
        else:
            proxy_ep = self._proxy_ep

        # socks_proto = yield proxy_ep.connect(socks_factory)
        yield proxy_ep.connect(socks_factory)
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

    def __init__(self, done, host, port, socks_method, factory):
        """
        Private implementation detail -- do not instantiate directly. Use
        one of: resolve(), resolve_ptr() or TorSocksEndpoint

        :param done: a Deferred that will be callback()d with the
            address requested for RESOLVE or RESOLVE_PTR, or for the
            underlying (wrapped) protocol if the request was CONNECT.
        """
        self._done = done
        self._host = host[:255]
        if isinstance(self._host, six.text_type):
            self._host = self._host.encode('ascii')
        self._port = port
        assert port == int(port)
        assert port >= 0 and port < 2 ** 16
        self._auth_method = 0x02  # "USERNAME/PASSWORD"
        methods = {
            'CONNECT': 0x01,      # plain SOCKS5
            'RESOLVE': 0xf0,      # Tor-only extension
            'RESOLVE_PTR': 0xf1,  # Tor-only extension
        }
        assert socks_method in methods
        self._socks_method = methods[socks_method]
        if socks_method == 'CONNECT':
            assert factory is not None
        self._factory = factory
        if self._socks_method == 0x01:
            self._done.addCallback(self._make_connection)
            # for CONNECT, we must have a factory
            assert self._factory is not None
        else:
            # for RESOLVE/RESOLVE_PTR, we should not have a factory
            assert self._factory is None

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
        if self._done and not self._done.called:
            self._done.errback(
                Failure(
                    SocksError(self.error_code_to_string[reply])
                )
            )
        self.transport.loseConnection()
        # connectionLost will (try to) errback on self._done, but we
        # do it above so that we can pass the actual error-message

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
        if typ == 0x01:         # IPv4
            addr = inet_ntoa(msg[4:8])
        elif typ == 0x03:       # DOMAINNAME
            addrlen = struct.unpack('B', msg[4:5])[0]
            addr = msg[5:5 + addrlen]
        elif typ == 0x04:       # IPv6
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
                5,                   # version
                self._socks_method,  # command
                0x00,                # reserved
                0x01,                # IPv4 address
                inet_aton(self._host),
                self._port,
            )
        else:
            data = struct.pack(
                '!BBBBB{}sH'.format(len(self._host)),
                5,                   # version
                self._socks_method,  # command
                0x00,                # reserved
                0x03,                # DOMAINNAME
                len(self._host),
                self._host,
                self._port,
            )
        self.transport.write(data)

    def connectionMade(self):
        # Ultimately, we need to funnel the source-port through to the
        # TorCircuitEndpoint and friends -- so we do so via
        # get_address / did_connect on the factory (happy to entertain
        # better ideas).
        self.factory._did_connect(self.transport.getHost())
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
        # print("dataReceived({} bytes): {}".format(len(d), repr(d)))
        self._fsm.process(d)
        return


class _TorSocksFactory(Factory):
    protocol = _TorSocksProtocol

    def __init__(self, *args, **kw):
        self._args = args
        self._kw = kw
        self._connected_d = []
        self._host = None

    def get_address(self):
        """
        Returns a Deferred that fires with the IAddress from the transport
        when this SOCKS protocol becomes connected.
        """
        d = Deferred()
        if self._host:
            d.callback(self._host)
        else:
            self._connected_d.append(d)
        return d

    def _did_connect(self, host):
        self._host = host
        for d in self._connected_d:
            d.callback(host)
        self._connected_d = None

    def buildProtocol(self, addr):
        p = self.protocol(*self._args, **self._kw)
        p.factory = self
        return p
