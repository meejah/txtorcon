# in-progress; implementing SOCKS5 client-side stuff as extended by
# tor because txsocksx will not be getting Python3 support any time
# soon, and its underlying dependency (Parsely) also doesn't support
# Python3. Also, Tor's SOCKS5 implementation is especially simple,
# since it doesn't do BIND or UDP ASSOCIATE.

from __future__ import print_function

import struct
from socket import inet_aton, inet_ntoa
from ipaddress import ip_address

from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks, returnValue, Deferred
from twisted.internet.interfaces import IProtocolFactory
from twisted.internet.protocol import Protocol, Factory
from twisted.internet.endpoints import TCP4ClientEndpoint

from txtorcon.spaghetti import FSM, State, Transition



@inlineCallbacks
def resolve(tor_endpoint, hostname):
    done = Deferred()
    factory = Factory.forProtocol(
        lambda: TorSocksProtocol(done, hostname, 0, 'RESOLVE')
    )
    proto = yield tor_endpoint.connect(factory)
    result = yield done
    returnValue(result)


class TorSocksProtocol(Protocol):
    @classmethod
    @inlineCallbacks
    def connect(cls, host, port):
        d = Deferred()
        tsp = TorSocksProtocol(d, host, port, 'CONNECT')
        yield d
        returnValue(tsp)

    @classmethod
    @inlineCallbacks
    def resolve_ptr(cls, ip_addr):
        d = Deferred()
        tsp = TorSocksProtocol(d, ip_addr, 0, 'RESOLVE_PTR')
        yield d
        returnValue(tsp)

    def __init__(self, done, host, port, socks_method):
        """
        Do not instantiate directly; use a factory method (one of the
        @classmethods of this class).
        """
        self._done = done
        self._host = host[:255]
        self._port = port
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

    def _error(self, msg):
        reply = struct.unpack('B', msg[1:2])[0]
        print("error; aborting SOCKS:", reply)
        self.transport.loseConnection()
        # connectionLost will errback on self._done

    def _relay_data(self, data):
        print("relay {} bytes".format(data))
        self.transport.write(data)

    def _is_valid_response(self, msg):
        print("_is_valid_response", msg)
        try:
            (version, reply, _, typ) = struct.unpack('BBBB', msg[:4])
            return version == 5 and reply == 0 and typ in [0x01, 0x03]
        except Exception as e:
            print("error", e)
            return False

    def _parse_response(self, msg):
        (version, reply, _, typ) = struct.unpack('BBBB', msg[:4])
        if typ == 0x01: # IPv4
            addr = inet_ntoa(msg[4:8])
        elif typ == 0x03:  # DOMAINNAME
            addrlen = struct.unpack('B', msg[4:5])[0]
            addr = msg[5:5 + addrlen]
        else:
            raise Exception("logic error")
        port = struct.unpack('H', msg[-2:])[0]
        self._reply_addr = addr
        self._reply_port = port
        print("reply {} {}".format(addr, port))
        if self._socks_method in [0xf0, 0xf1]:
            self._done.callback(addr)
            self.transport.loseConnection()
            return self._sent_version_state

    def _is_valid_version(self, msg):
        print("_is_valid_version", msg)
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
        atyp = 0x03  # DOMAINNAME
        host = self._host
        if self._socks_method == 0xf1:
            atyp = 0x01  # IPv4 Address
            host = inet_aton(self._host)
        data = struct.pack(
            '!BBBBB{}sH'.format(len(host)),
            5,                  # version
            self._socks_method, # command
            0x00,               # reserved
            atyp,               # ATYP
            len(host),
            host,
            self._port,
        )
        print("sending req", repr(data))
        self.transport.write(data)


    def connectionMade(self):
        self._fsm.state = self._fsm.states[0]  # SENT_VERSION
        # ask for 2 methods: 0 (anonymous) and 2 (authenticated)
        data = struct.pack('BBBB', 5, 2, 0, 2)
        # ask for 1 methods: 0 (anonymous)
        data = struct.pack('BBB', 5, 1, 0)
        self.transport.write(data)

    def connectionLost(self, reason):
        ##print("lost", reason)
        if not self._done.called:
            self._done.callback(reason)

    def dataReceived(self, d):
        print("data!", d)
        self._fsm.process(d)
        return

        if self._state == 'wait_version':
            (version, method) = struct.unpack('bb', d)
            assert version == 5  # version
            if method == 0xff:
                self.transport.loseConnection()
            assert method in [0, 2]

            # WTF??! why doesn't the 'p' format character work?

            # send a command
            data = struct.pack(
                '!BBBBB{}sH'.format(len(self._host)),
                5,              # version
                0x01,           # command (CONNECT)
                #0xf0,           # command (RESOLVE) custom tor thing
                0x00,           # reserved
                0x03,           # ATYP (DOMAINNAME)
                len(self._host),
                self._host,
                self._port,
            )
            print("sending", data)
            self.transport.write(data)
            self._state = 'sent_command'
        elif self._state == 'sent_command':
            self._state = 'relaying'
            (version, reply, _, typ) = struct.unpack('BBBB', d[:4])
            print(version, reply, typ)
            if reply != 0x00:
                print("FAIL: {}".format(reply))
            if typ != 0x01:
                print("only know IPv4")
            (addr, port) = struct.unpack('!IH', d[4:])
            print(reply, typ, addr, port)
            print("ADDR", ip_address(addr), port)
            self.transport.write(b'GET / HTTP/1.1\r\nHost: timaq4ygg2iegci7.onion\r\n\r\n')


class TorSocksFactory(Factory):
    def __init__(self, host, port):
        self._host = host
        self._port = port
        self._done = Deferred()

    def buildProtocol(self, addr):
        print("buiLD", addr)
        return TorSocksProtocol(self._done, self._host, self._port)


@inlineCallbacks
def main(reactor):
    #factory = TorSocksFactory('torproject.org', 443)
    #factory = TorSocksFactory('torproject.org', 80)
    #factory = TorSocksFactory('hedgeivoyioq5trz.onion', 80)
    #factory = TorSocksFactory('timaq4ygg2iegci7.onion', 80)
    addr = yield resolve(
        TCP4ClientEndpoint(reactor, '127.0.0.1', 9050),
        'torproject.org',
    )
    print("result:", addr)

if __name__ == '__main__':
    react(main)
