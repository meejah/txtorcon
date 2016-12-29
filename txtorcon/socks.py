# in-progress; implementing SOCKS5 client-side stuff as extended by
# tor because txsocksx will not be getting Python3 support any time
# soon, and its underlying dependency (Parsely) also doesn't support
# Python3. Also, Tor's SOCKS5 implementation is especially simple,
# since it doesn't do BIND or UDP ASSOCIATE.

from __future__ import print_function

import six
import struct
from socket import inet_aton, inet_ntoa
import functools

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
from txtorcon import util


# okay, so what i want to do to fix this crap up is:
# - state-machine is separate (doesn't do parsing)
# - parsing incoming data into symbols for the state-machine
# - (the parser sadly has to know the current state, because no SOCKS framing)
# - ideally also make it "IO neutral", i.e. so could be basis for a
#   synchronous SOCKS thing

# so, e.g. states ge


_socks_reply_code_to_string = {
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

import automat

class SocksMachine(object):
    """
    trying to prototype the SOCKS state-machine in automat

    This is a SOCKS state machine to make a single request.
    """
    _machine = automat.MethodicalMachine()

    # XXX address = (host, port) instead
    def __init__(self, req_type, host, port=0,
                 on_disconnect=None,
                 on_data=None):
        if req_type not in self._dispatch:
            raise ValueError(
                "Unknown request type '{}'".format(req_type)
            )
        self._req_type = req_type
        self._host = host
        self._port = port
        self._data = b''
        self._on_disconnect = on_disconnect
        # XXX FIXME do *one* of these:
        self._on_data = on_data
        self._outgoing_data = []
        # the other side of our proxy
        self._sender = None
        self._when_done = util.SingleObserver()

##    @util.observable
    def when_done(self):
        """
        Returns a Deferred that fires when we're done
        """
        return self._when_done.when_fired()

    def _data_to_send(self, data):
        if self._on_data:
            self._on_data(data)
        else:
            self._outgoing_data.append(data)

    def send_data(self, callback):
        while len(self._outgoing_data):
            data = self._outgoing_data.pop(0)
            callback(data)

    def feed_data(self, data):
        # I feel like maybe i'm doing all this buffering-stuff
        # wrong. but I also don't want a bunch of "received 1 byte"
        # etc states hanging off everything that can "get data"
        self._data += data
        self.got_data()

    @_machine.output()
    def _parse_version_reply(self):
        "waiting for a version reply"
        if len(self._data) >= 2:
            reply = self._data[:2]
            self._data = self._data[2:]
            (version, method) = struct.unpack('BB', reply)
            if version == 5 and method in [0x00, 0x02]:
                self.version_reply(method)
            else:
                print("HERE", version, self)
                if version != 5:
                    self.version_error("Expected version 5, got {}".format(version))
                else:
                    self.version_error("Wanted method 0 or 2, got {}".format(method))

    def _ipv4_reply(self):
        if len(self._data) >= 10:
            addr = inet_ntoa(self._data[4:8])
            port = struct.unpack('H', self._data[8:10])[0]
            self._data = self._data[10:]
            self.reply_ipv4(addr, port)

    def _ipv6_reply(self):
        if len(self._data) >= 22:
            addr = msg[4:20]
            port = struct.unpack('H', self._data[2:22])[0]
            self._data = self._data[22:]
            self.reply_ipv6(addr, port)

    def _hostname_reply(self):
        if len(self._data) < 8:
            return
        addrlen = struct.unpack('B', self._data[4:5])[0]
        # may simply not have received enough data yet...
        if len(self._data) < (5 + addrlen + 2):
            return
        addr = self._data[5:5 + addrlen]
        port = struct.unpack('H', self._data[5 + addrlen:5 + addrlen + 2])[0]
        self._data = self._data[5 + addrlen + 2:]
        # ignoring port -- don't think it's used?
        self.reply_domain_name(addr)



    @_machine.output()
    def _parse_request_reply(self):
        "waiting for a reply to our request"
        # we need at least 6 bytes of data: 4 for the "header", such
        # as it is, and 2 more if it's DOMAINNAME (for the size) or 4
        # or 16 more if it's an IPv4/6 address reply. plus there's 2
        # bytes on the end for the bound port.

        if len(self._data) < 8:
            return
        msg = self._data[:4]

        # not changing self._data yet, in case we've not got
        # enough bytes so far.
        (version, reply, _, typ) = struct.unpack('BBBB', msg)

        if version != 5:
            self.reply_error("Expected version 5, got {}".format(version))
            return

        if reply != 0:
            # reply == 0x00 is "succeeded", else there are error codes
            try:
                self.reply_error(_socks_reply_code_to_string[reply])
            except KeyError:
                self.reply_error("Unknown reply code {}".format(reply))
            return

        type_dispatch = {
            0x01: self._ipv4_reply,
            0x03: self._hostname_reply,
            0x04: self._ipv6_reply,
        }
        try:
            type_dispatch[typ]()
        except KeyError:
            self.reply_error("Unexpected response type {}".format(typ))

    @_machine.output()
    def _make_connection(self, addr, port):
        "make our proxy connection"
        addr = IPv4Address('TCP', addr, port)
        sender = yield self._factory.buildProtocol(addr)
        client_proxy = portforward.ProxyClient()
        sender.makeConnection(self.transport)
        # portforward.ProxyClient is going to call setPeer but this
        # probably doesn't have it...
        setattr(sender, 'setPeer', lambda _: None)
        client_proxy.setPeer(sender)
        self._sender = sender
        returnValue(sender)

    @_machine.input()
    def connection(self):
        "begin the protocol (i.e. connection made)"

    @_machine.input()
    def disconnected(self, error_message):
        "the connection has gone away"

    @_machine.input()
    def got_data(self):
        "we recevied some data and buffered it"

    @_machine.input()
    def version_reply(self, method):
        "the SOCKS server replied with a version"

    @_machine.input()
    def version_error(self, error_message):
        "the SOCKS server replied, but we don't understand"

    @_machine.input()
    def reply_error(self, error_message):
        "the SOCKS server replied with an error"

    @_machine.input()
    def reply_ipv4(self, addr, port):
        "the SOCKS server told me an IPv4 addr, port"

    @_machine.input()
    def reply_ipv6(self, addr, port):
        "the SOCKS server told me an IPv6 addr, port"

    @_machine.input()
    def reply_domain_name(self, domain):
        "the SOCKS server told me a domain-name"

    @_machine.input()
    def answer(self):
        "the SOCKS server replied with an answer"

    @_machine.input()
    def relay_reply(self):
        "the SOCKS server told us its relaying"

    @_machine.output()
    def _send_version(self):
        "sends a SOCKS version reply"
        self._data_to_send(
            # for anonymous(0) *and* authenticated (2): struct.pack('BBBB', 5, 2, 0, 2)
            struct.pack('BBB', 5, 1, 0)
        )

    @_machine.output()
    def _disconnect(self, error_message):
        "done"
        if self._on_disconnect:
            self._on_disconnect(error_message)
        if self._sender:
            self._sender.connectionLost(SocksError(error_message))
        # XXX what's the 'happy path' exit? i.e. do we ever .fire()
        # without a Failure?
        self._when_done.fire(Failure(SocksError(error_message)))
        #if not self._done.called:
        #    self._done.callback(reason)

    @_machine.output()
    def _send_request(self, method):
        "send the request (connect, resolve or resolve_ptr)"
        print("_send_request", method)
        return self._dispatch[self._req_type](self)

    @_machine.output()
    def _relay_data(self):
        "relay any data we have"
        if self._data:
            d = self._data
            self._data = b''
            self._data_to_send(d)

    def _send_connect_request(self):
        "sends CONNECT request"
        self._data_to_send(
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
        self._data_to_send(
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
        self._data_to_send(
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

    @_machine.state()
    def relaying(self):
        "received our response, now we can relay"

    @_machine.state()
    def abort(self, error_message):
        "we've encountered an error"

    unconnected.upon(
        connection,
        enter=sent_version,
        outputs=[_send_version],
    )

    sent_version.upon(
        got_data,
        enter=sent_version,
        outputs=[_parse_version_reply],
    )
    sent_version.upon(
        version_error,
        enter=abort,
        outputs=[_disconnect],
    )
    sent_version.upon(
        version_reply,
        enter=sent_request,
        outputs=[_send_request],
    )
    sent_version.upon(
        disconnected,
        enter=unconnected,
        outputs=[_disconnect]
    )

    sent_request.upon(
        got_data,
        enter=sent_request,
        outputs=[_parse_request_reply],
    )
    sent_request.upon(
        reply_ipv4,
        enter=relaying,
        outputs=[_make_connection],
    )
    sent_request.upon(
        reply_error,
        enter=abort,
        outputs=[_disconnect],
    )

    relaying.upon(
        got_data,
        enter=relaying,
        outputs=[_relay_data],
    )

    abort.upon(
        got_data,
        enter=abort,
        outputs=[],
    )
    abort.upon(
        disconnected,
        enter=abort,
        outputs=[],
    )

#    sent_version.upon(
#        error_reply,
#        # we could go back to 'sent_version' if we had some way to
#        # remember / input (type, host, port) as an @input
#        enter=abort,
#        output=[_close_connection]
#    )
#    sent_version.upon(
#        answer,
#        enter=got_answer,
#        output=[_start_relay]
#    )


    _dispatch = {
        'CONNECT': _send_connect_request,
        'RESOLVE': _send_resolve_request,
        'RESOLVE_PTR': _send_resolve_ptr_request,
    }


class _TorSocksProtocol2(Protocol):

    def __init__(self, host, port, socks_method, factory):
        print("made a proto", host)
        self._machine = SocksMachine(
            req_type=socks_method,
            host=host,
            port=port,
            on_disconnect=self._on_disconnect,
            on_data=self._on_data,
        )

    def connectionMade(self):
        print("connection!")
        self._machine.connection()

    def connectionLost(self, reason):
        print("LOST", reason)
        self._machine.disconnected(reason)

    def dataReceived(self, data):
        print("DATA", repr(data))
        self._machine.feed_data(data)

    def _on_data(self, data):
        print("sending", data)
        self.transport.write(data)

    def _on_disconnect(self, error_message):
        print("DISCONNECTED!", error_message)
        print(dir(self.transport))
        self.transport.loseConnection()
        print("self.transport", self.transport, self.transport.disconnected)
        #self.transport.abortConnection()#SocksError(error_message))
        #self._machine.disconnect(error_message)


class _TorSocksFactory2(Factory):
    protocol = _TorSocksProtocol2

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
        print("doing error", repr(msg))
        try:
            reply = struct.unpack('B', msg[1:2])[0]
            f = Failure(
                SocksError(self.error_code_to_string[reply])
            )
        except KeyError:
            f = Failure(
                Exception("No such SOCKS reply code '{}'".format(reply))
            )
        except Exception:
            f = Failure(
                Exception("Internal error processing error-reply")
            )
        if self._done and not self._done.called:
            self._done.errback(f)
        else:
            print("Unreportable error {}".format(f))
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
