from zope.interface import implements
from zope.interface.verify import verifyClass
from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.internet import task, defer, endpoints, reactor
from twisted.internet.interfaces import IStreamClientEndpoint, IReactorCore

import os
import subprocess

from txtorcon import TorControlProtocol, TorProtocolError, TorState, Stream, Circuit, build_tor_connection
from txtorcon.interface import ITorControlProtocol, IStreamAttacher, ICircuitListener, IStreamListener, StreamListenerMixin, CircuitListenerMixin

def do_nothing(*args):
    pass

class CircuitListener(object):
    implements(ICircuitListener)
    
    def __init__(self, expected):
        "expect is a list of tuples: (event, {key:value, key1:value1, ..})"
        self.expected = expected

    def checker(self, state, circuit, arg=None):
        if self.expected[0][0] != state:
            raise RuntimeError('Expected event "%s" not "%s".'%(self.expected[0][0], state))
        for (k,v) in self.expected[0][1].items():
            if k == 'arg':
                if v != arg:
                    raise RuntimeError('Expected argument to have value "%s", not "%s"' % (arg, v))
            elif getattr(circuit, k) != v:
                raise RuntimeError('Expected attribute "%s" to have value "%s", not "%s"' % (k, v, getattr(circuit, k)))
        self.expected = self.expected[1:]
            
    def circuit_new(self, circuit):
        self.checker('new', circuit)
    
    def circuit_launched(self, circuit):
        self.checker('launched', circuit)

    def circuit_extend(self, circuit, router):
        self.checker('extend', circuit, router)

    def circuit_built(self, circuit):
        self.checker('built', circuit)

    def circuit_closed(self, circuit):
        self.checker('closed', circuit)
        
    def circuit_failed(self, circuit, reason):
        self.checker('failed', circuit, reason)
    
class StreamListener(object):
    implements(IStreamListener)
    
    def __init__(self, expected):
        "expect is a list of tuples: (event, {key:value, key1:value1, ..})"
        self.expected = expected

    def checker(self, state, stream, arg=None):
        if self.expected[0][0] != state:
            raise RuntimeError('Expected event "%s" not "%s".'%(self.expected[0][0], state))
        for (k,v) in self.expected[0][1].items():
            if k == 'arg':
                if v != arg:
                    raise RuntimeError('Expected argument to have value "%s", not "%s"' % (arg, v))
            elif getattr(stream, k) != v:
                raise RuntimeError('Expected attribute "%s" to have value "%s", not "%s"' % (k, v, getattr(stream, k)))
        self.expected = self.expected[1:]
            
    def stream_new(self, stream):
        self.checker('new', stream)
    
    def stream_succeeded(self, stream):
        self.checker('succeeded', stream)
    
    def stream_attach(self, stream, circuit):
        self.checker('attach', stream, circuit)

    def stream_closed(self, stream):
        self.checker('closed', stream)

    def stream_failed(self, stream, reason, remote_reason):
        self.checker('failed', stream, reason)
    
class FakeReactor:
    implements(IReactorCore)

    def __init__(self, test):
        self.test = test

    def addSystemEventTrigger(self, *args):
        self.test.assertEqual(args[0], 'before')
        self.test.assertEqual(args[1], 'shutdown')
        self.test.assertEqual(args[2], self.test.state.undo_attacher)
        return 1
    def removeSystemEventTrigger(self, id):
        self.test.assertEqual(id, 1)

class FakeCircuit:
    def __init__(self, id=-999):
        self.streams = []
        self.id = id
        self.state = 'BOGUS'

class FakeEndpoint:
    implements(IStreamClientEndpoint)

    def get_info_raw(self, keys):
        return defer.succeed('\r\n'.join(map(lambda k: '%s='%k, keys.split())))

    def get_info_incremental(self, key, linecb):
        linecb('%s='%key)
        return defer.succeed('')

    def connect(self, protocol_factory):
        self.proto = TorControlProtocol()
        self.proto.transport = proto_helpers.StringTransport()
        self.proto.get_info_raw = self.get_info_raw
        self.proto.get_info_incremental = self.get_info_incremental
        self.proto._set_valid_events('GUARD STREAM CIRC NS NEWCONSENSUS ORCONN NEWDESC ADDRMAP STATUS_GENERAL')

        return defer.succeed(self.proto)

class FakeEndpointAnswers:
    implements(IStreamClientEndpoint)

    def __init__(self, answers):
        self.answers = answers
        # since we use pop() we need these to be "backwards"
        self.answers.reverse()

    def get_info_raw(self, keys):
        ans = ''
        for k in keys.split():
            if len(self.answers) == 0:
                raise TorProtocolError(551, "ran out of answers")
            ans += '%s=%s\r\n' % (k, self.answers.pop())
        return ans[:-2]                 # don't want trailing \r\n

    def get_info_incremental(self, key, linecb):
        linecb('%s=%s' % (key, self.answers.pop()))
        return defer.succeed('')

    def connect(self, protocol_factory):
        self.proto = TorControlProtocol()
        self.proto.transport = proto_helpers.StringTransport()
        self.proto.get_info_raw = self.get_info_raw
        self.proto.get_info_incremental = self.get_info_incremental
        self.proto._set_valid_events('GUARD STREAM CIRC NS NEWCONSENSUS ORCONN NEWDESC ADDRMAP STATUS_GENERAL')

        return defer.succeed(self.proto)

class FakeControlProtocol:
    implements(ITorControlProtocol)     # actually we don't, it's a lie

    def __init__(self):
        self.is_owned = None
        self.post_bootstrap = defer.succeed(self)

class InternalMethodsTests(unittest.TestCase):

    def test_state_diagram(self):
        state = TorState(FakeControlProtocol(), bootstrap=False, write_state_diagram=True)
        self.assertTrue(os.path.exists('routerfsm.dot'))
        
class BootstrapTests(unittest.TestCase):

    def confirm_proto(self, x):
        self.assertTrue(isinstance(x, TorControlProtocol))
        self.assertTrue(x.post_bootstrap.called)
        
    def confirm_state(self, x):
        self.assertTrue(isinstance(x, TorState))
        self.assertTrue(x.post_bootstrap.called)
        return x

    def test_build(self):
        p = FakeEndpoint()
        d = build_tor_connection(p, build_state=False)
        d.addCallback(self.confirm_proto)
        p.proto.post_bootstrap.callback(p.proto)
        return d

    def confirm_pid(self, state):
        self.assertEqual(state.tor_pid, 1234)

    def confirm_no_pid(self, state):
        self.assertEqual(state.tor_pid, 0)

    def test_build_with_answers(self):
        p = FakeEndpointAnswers(['',    # ns/all
                                 '',    # circuit-status
                                 '',    # stream-status
                                 '',    # address-mappings/all
                                 '',    # entry-guards
                                 '1234' # PID
                                 ])

        d = build_tor_connection(p, build_state=True)
        d.addCallback(self.confirm_state).addErrback(self.fail)
        d.addCallback(self.confirm_pid).addErrback(self.fail)
        p.proto.post_bootstrap.callback(p.proto)
        return d

    def test_build_with_answers_no_pid(self):
        p = FakeEndpointAnswers(['',    # ns/all
                                 '',    # circuit-status
                                 '',    # stream-status
                                 '',    # address-mappings/all
                                 ''     # entry-guards
                                 ])

        d = build_tor_connection(p, build_state=True)
        d.addCallback(self.confirm_state)
        d.addCallback(self.confirm_no_pid)
        p.proto.post_bootstrap.callback(p.proto)
        return d

class StateTests(unittest.TestCase):
    def setUp(self):
        self.protocol = TorControlProtocol()
        self.state = TorState(self.protocol)
        self.protocol.connectionMade = do_nothing
        self.transport = proto_helpers.StringTransport()
        self.protocol.makeConnection(self.transport)

    def test_close_stream_with_attacher(self):
        class MyAttacher(object):
            implements(IStreamAttacher)

            def __init__(self):
                self.streams = []

            def attach_stream(self, stream, circuits):
                self.streams.append(stream)
                return None

        attacher = MyAttacher()
        self.state.set_attacher(attacher, FakeReactor(self))
        self.state._stream_update("76 CLOSED 0 www.example.com:0 REASON=DONE")

    def test_stream_update(self):
        ## we use a circuit ID of 0 so it doesn't try to look anything up but it's
        ## not really correct to have a  SUCCEEDED w/o a valid circuit, I don't think
        self.state._stream_update('1610 SUCCEEDED 0 74.125.224.243:80')
        self.assertTrue(self.state.streams.has_key(1610))

    def test_single_streams(self):
        self.state.circuits[496] = FakeCircuit(496)
        self.state._stream_status('stream-status=123 SUCCEEDED 496 www.example.com:6667\r\nOK')
        self.assertEqual(len(self.state.streams), 1)

    def send(self, line):
        self.protocol.dataReceived(line.strip() + "\r\n")
        
    def test_bootstrap_callback(self):
        '''
        FIXME: something is still screwy with this; try throwing an
        exception from TorState.bootstrap and we'll just hang...
        '''
        
        d = self.state.post_bootstrap
        
        self.protocol._set_valid_events(' '.join(self.state.event_map.keys()))
        self.state._bootstrap()

        self.send("250+ns/all=")
        self.send(".")
        self.send("250 OK")

        self.send("250+circuit-status=")
        self.send(".")
        self.send("250 OK")

        self.send("250-stream-status=")
        self.send("250 OK")

        self.send("250-address-mappings/all=")
        self.send("250 OK")

        for ignored in self.state.event_map.items():
            self.send("250 OK")

        fakerouter = object()
        self.state.routers['$0000000000000000000000000000000000000000'] = fakerouter
        self.state.routers['$9999999999999999999999999999999999999999'] = fakerouter
        self.send("250+entry-guards=")
        self.send("$0000000000000000000000000000000000000000=name up")
        self.send("$1111111111111111111111111111111111111111=foo up")
        self.send("$9999999999999999999999999999999999999999=eman unusable 2012-01-01 22:00:00")
        self.send(".")
        self.send("250 OK")

        ## implicitly created Router object for the $1111...11 lookup
        ## but 0.0.0.0 will have to country, so Router will ask Tor
        ## for one via GETINFO ip-to-country
        self.send("250-ip-to-country/0.0.0.0=??")
        self.send("250 OK")

        self.assertEqual(len(self.state.entry_guards), 2)
        self.assertTrue(self.state.entry_guards.has_key('$0000000000000000000000000000000000000000'))
        self.assertEqual(self.state.entry_guards['$0000000000000000000000000000000000000000'], fakerouter)
        self.assertTrue(self.state.entry_guards.has_key('$1111111111111111111111111111111111111111'))

        self.assertEqual(len(self.state.unusable_entry_guards), 1)
        self.assertTrue('$9999999999999999999999999999999999999999' in self.state.unusable_entry_guards[0])
        
        return d
        
    def test_bootstrap_existing_addresses(self):
        '''
        FIXME: something is still screwy with this; try throwing an
        exception from TorState.bootstrap and we'll just hang...
        '''
        
        d = self.state.post_bootstrap

        clock = task.Clock()
        self.state.addrmap.scheduler = clock
        
        self.protocol._set_valid_events(' '.join(self.state.event_map.keys()))
        self.state._bootstrap()

        self.send("250+ns/all=")
        self.send(".")
        self.send("250 OK")

        self.send("250+circuit-status=")
        self.send(".")
        self.send("250 OK")

        self.send("250-stream-status=")
        self.send("250 OK")

        self.send("250+address-mappings/all=")
        self.send('www.example.com 127.0.0.1 "2012-01-01 00:00:00"')
        self.send('subdomain.example.com 10.0.0.0 "2012-01-01 00:01:02"')
        self.send('.')
        self.send('250 OK')

        for ignored in self.state.event_map.items():
            self.send("250 OK")

        self.send("250-entry-guards=")
        self.send("250 OK")

        self.send("250 OK")

        self.assertEqual(len(self.state.addrmap.addr), 2)
        self.assertTrue(self.state.addrmap.addr.has_key('www.example.com'))
        self.assertTrue(self.state.addrmap.addr.has_key('subdomain.example.com'))

        return d

    def test_unset_attacher(self):
        class MyAttacher(object):
            implements(IStreamAttacher)
            def attach_stream(self, stream, circuits):
                return None

        fr = FakeReactor(self)
        self.state.set_attacher(MyAttacher(), fr)
        self.send("250 OK")
        self.state.set_attacher(None, fr)
        self.send("250 OK")
        self.assertEqual(self.transport.value(), 'SETCONF __LeaveStreamsUnattached=1\r\nSETCONF __LeaveStreamsUnattached=0\r\n')
        
    def test_attacher(self):
        class MyAttacher(object):
            implements(IStreamAttacher)

            def __init__(self):
                self.streams = []
                self.answer = None

            def attach_stream(self, stream, circuits):
                self.streams.append(stream)
                return self.answer

        attacher = MyAttacher()
        self.state.set_attacher(attacher, FakeReactor(self))
        events = 'GUARD STREAM CIRC NS NEWCONSENSUS ORCONN NEWDESC ADDRMAP STATUS_GENERAL'
        self.protocol._set_valid_events(events)
        self.state._add_events()
        for ignored in self.state.event_map.items():
            self.send("250 OK")

        self.send("650 STREAM 1 NEW 0 ca.yahoo.com:80 SOURCE_ADDR=127.0.0.1:54327 PURPOSE=USER")
        self.send("650 STREAM 1 REMAP 0 87.248.112.181:80 SOURCE=CACHE")
        self.assertEqual(len(attacher.streams), 1)
        self.assertEqual(attacher.streams[0].id, 1)
        self.assertEqual(len(self.protocol.commands), 1)
        self.assertEqual(self.protocol.commands[0][1], 'ATTACHSTREAM 1 0')

        # we should totally ignore .exit URIs
        attacher.streams = []
        self.send("650 STREAM 2 NEW 0 10.0.0.0.$E11D2B2269CC25E67CA6C9FB5843497539A74FD0.exit:80 SOURCE_ADDR=127.0.0.1:12345 PURPOSE=TIME")
        self.assertEqual(len(attacher.streams), 0)
        self.assertEqual(len(self.protocol.commands), 1)

        # we should NOT ignore .onion URIs
        attacher.streams = []
        self.send("650 STREAM 3 NEW 0 xxxxxxxxxxxxxxxx.onion:80 SOURCE_ADDR=127.0.0.1:12345 PURPOSE=TIME")
        self.assertEqual(len(attacher.streams), 1)
        self.assertEqual(len(self.protocol.commands), 2)
        self.assertEqual(self.protocol.commands[1][1], 'ATTACHSTREAM 3 0')

        # normal attach
        circ = FakeCircuit(1)
        circ.state = 'BUILT'
        self.state.circuits[1] = circ
        attacher.answer = circ
        self.send("650 STREAM 4 NEW 0 xxxxxxxxxxxxxxxx.onion:80 SOURCE_ADDR=127.0.0.1:12345 PURPOSE=TIME")
        self.assertEqual(len(attacher.streams), 2)
        self.assertEqual(len(self.protocol.commands), 3)
        self.assertEqual(self.protocol.commands[2][1], 'ATTACHSTREAM 4 1')

    def test_attacher_defer(self):
        class MyAttacher(object):
            implements(IStreamAttacher)

            def __init__(self, answer):
                self.streams = []
                self.answer = answer

            def attach_stream(self, stream, circuits):
                self.streams.append(stream)
                return defer.succeed(self.answer)

        self.state.circuits[1] = FakeCircuit(1)
        attacher = MyAttacher(self.state.circuits[1])
        self.state.set_attacher(attacher, FakeReactor(self))

        ## boilerplate to finish enough set-up in the protocol so it
        ## works
        events = 'GUARD STREAM CIRC NS NEWCONSENSUS ORCONN NEWDESC ADDRMAP STATUS_GENERAL'
        self.protocol._set_valid_events(events)
        self.state._add_events()
        for ignored in self.state.event_map.items():
            self.send("250 OK")

        self.send("650 STREAM 1 NEW 0 ca.yahoo.com:80 SOURCE_ADDR=127.0.0.1:54327 PURPOSE=USER")
        self.send("650 STREAM 1 REMAP 0 87.248.112.181:80 SOURCE=CACHE")
        self.assertEqual(len(attacher.streams), 1)
        self.assertEqual(attacher.streams[0].id, 1)
        self.assertEqual(len(self.protocol.commands), 1)
        self.assertEqual(self.protocol.commands[0][1], 'ATTACHSTREAM 1 1')


    def test_attacher_errors(self):
        class MyAttacher(object):
            implements(IStreamAttacher)

            def __init__(self, answer):
                self.streams = []
                self.answer = answer

            def attach_stream(self, stream, circuits):
                return self.answer

        self.state.circuits[1] = FakeCircuit(1)
        attacher = MyAttacher(FakeCircuit(2))
        self.state.set_attacher(attacher, FakeReactor(self))

        stream = Stream(self.state)
        stream.id = 3
        msg = ''
        try:
            self.state._maybe_attach(stream)
        except Exception, e:
            msg = str(e)
        self.assertTrue('circuit unknown' in msg)

        attacher.answer = self.state.circuits[1]
        msg = ''
        try:
            self.state._maybe_attach(stream)
        except Exception, e:
            msg = str(e)
        self.assertTrue('only attach to BUILT' in msg)

    def test_attacher_no_attach(self):
        class MyAttacher(object):
            implements(IStreamAttacher)

            def __init__(self):
                self.streams = []

            def attach_stream(self, stream, circuits):
                self.streams.append(stream)
                return TorState.DO_NOT_ATTACH

        attacher = MyAttacher()
        self.state.set_attacher(attacher, FakeReactor(self))
        events = 'GUARD STREAM CIRC NS NEWCONSENSUS ORCONN NEWDESC ADDRMAP STATUS_GENERAL'
        self.protocol._set_valid_events(events)
        self.state._add_events()
        for ignored in self.state.event_map.items():
            self.send("250 OK")

        self.transport.clear()
        self.send("650 STREAM 1 NEW 0 ca.yahoo.com:80 SOURCE_ADDR=127.0.0.1:54327 PURPOSE=USER")
        self.send("650 STREAM 1 REMAP 0 87.248.112.181:80 SOURCE=CACHE")
        self.assertEqual(len(attacher.streams), 1)
        self.assertEqual(attacher.streams[0].id, 1)
        print self.transport.value()
        self.assertEqual(self.transport.value(), '')

    def test_close_stream(self):
        stream = Stream(self.state)
        stream.id = 1
        try:
            self.state.close_stream(stream)
            self.assertTrue(False)
        except KeyError:
            pass
        
        self.state.streams[1] = stream
        self.state.close_stream(stream)
        self.assertEqual(self.transport.value(), 'CLOSESTREAM 1 1\r\n')

    def test_circuit_destroy(self):
        self.state._circuit_update('365 LAUNCHED PURPOSE=GENERAL')
        self.assertTrue(self.state.circuits.has_key(365))
        self.state._circuit_update('365 FAILED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus,$253DFF1838A2B7782BE7735F74E50090D46CA1BC=chomsky PURPOSE=GENERAL REASON=TIMEOUT')
        self.assertTrue(not self.state.circuits.has_key(365))

    def test_circuit_destroy_already(self):
        self.state._circuit_update('365 LAUNCHED PURPOSE=GENERAL')
        self.assertTrue(self.state.circuits.has_key(365))
        c = self.state.circuits[365]
        self.state._circuit_update('365 CLOSED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus,$253DFF1838A2B7782BE7735F74E50090D46CA1BC=chomsky PURPOSE=GENERAL REASON=TIMEOUT')
        self.assertTrue(not self.state.circuits.has_key(365))
        self.state._circuit_update('365 CLOSED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus,$253DFF1838A2B7782BE7735F74E50090D46CA1BC=chomsky PURPOSE=GENERAL REASON=TIMEOUT')
        self.assertTrue(not self.state.circuits.has_key(365))

    def test_circuit_listener(self):
        events = 'CIRC STREAM ORCONN BW DEBUG INFO NOTICE WARN ERR NEWDESC ADDRMAP AUTHDIR_NEWDESCS DESCCHANGED NS STATUS_GENERAL STATUS_CLIENT STATUS_SERVER GUARD STREAM_BW CLIENTS_SEEN NEWCONSENSUS BUILDTIMEOUT_SET'
        self.protocol._set_valid_events(events)
        self.state._add_events()
        for ignored in self.state.event_map.items():
            self.send("250 OK")
        
        ## we use this router later on in an EXTEND
        self.state._update_network_status("""ns/all=
r PPrivCom012 2CGDscCeHXeV/y1xFrq1EGqj5g4 QX7NVLwx7pwCuk6s8sxB4rdaCKI 2011-12-20 08:34:19 84.19.178.6 9001 0
s Fast Guard Running Stable Unnamed Valid
w Bandwidth=51500
p reject 1-65535""")

        expected = [('new', {'id':456}),
                    ('launched', {}),
                    ('extend', {'id':123})
                    ]
        listen = CircuitListener(expected)
        ## first add a Circuit before we listen
        self.protocol.dataReceived("650 CIRC 123 LAUNCHED PURPOSE=GENERAL\r\n")
        self.assertEqual(len(self.state.circuits), 1)

        ## make sure we get added to existing circuits
        self.state.add_circuit_listener(listen)
        self.assertTrue(listen in self.state.circuits.values()[0].listeners)

        ## now add a Circuit after we started listening
        self.protocol.dataReceived("650 CIRC 456 LAUNCHED PURPOSE=GENERAL\r\n")
        self.assertEqual(len(self.state.circuits), 2)
        self.assertTrue(listen in self.state.circuits.values()[0].listeners)
        self.assertTrue(listen in self.state.circuits.values()[1].listeners)

        ## now update the first Circuit to ensure we're really, really
        ## listening
        self.protocol.dataReceived("650 CIRC 123 EXTENDED $D82183B1C09E1D7795FF2D7116BAB5106AA3E60E~PPrivCom012 PURPOSE=GENERAL\r\n")
        self.assertEqual(len(listen.expected), 0)

    def test_router_from_id_invalid_key(self):
        self.failUnlessRaises(KeyError, self.state.router_from_id, 'somethingcompletelydifferent..thatis42long')

    def test_router_from_named_router(self):
        r = self.state.router_from_id('$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=foo')
        self.assertEqual(r.id_hex, '$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
        self.assertEqual(r.unique_name, 'foo')

    def confirm_router_state(self, x):
        self.assertTrue(self.state.routers.has_key('$624926802351575FF7E4E3D60EFA3BFB56E67E8A'))
        router = self.state.routers['$624926802351575FF7E4E3D60EFA3BFB56E67E8A']
        self.assertTrue('exit' in router.flags)
        self.assertTrue('fast' in router.flags)
        self.assertTrue('guard' in router.flags)
        self.assertTrue('hsdir' in router.flags)
        self.assertTrue('named' in router.flags)
        self.assertTrue('running' in router.flags)
        self.assertTrue('stable' in router.flags)
        self.assertTrue('v2dir' in router.flags)
        self.assertTrue('valid' in router.flags)
        self.assertTrue('futureproof' in router.flags)
        self.assertEqual(router.bandwidth, 518000)
        self.assertTrue(router.accepts_port(43))
        self.assertTrue(router.accepts_port(53))
        self.assertTrue(not router.accepts_port(44))
        self.assertTrue(router.accepts_port(989))
        self.assertTrue(router.accepts_port(990))
        self.assertTrue(not router.accepts_port(991))
        self.assertTrue(not router.accepts_port(988))

    def test_invalid_routers(self):
        try:
            self.state._update_network_status('''ns/all=
r fake YkkmgCNRV1/35OPWDvo7+1bmfoo tanLV/4ZfzpYQW0xtGFqAa46foo 2011-12-12 16:29:16 12.45.56.78 443 80
r fake YkkmgCNRV1/35OPWDvo7+1bmfoo tanLV/4ZfzpYQW0xtGFqAa46foo 2011-12-12 16:29:16 12.45.56.78 443 80
s Exit Fast Guard HSDir Named Running Stable V2Dir Valid FutureProof
w Bandwidth=518000
p accept 43,53,79-81,110,143,194,220,443,953,989-990,993,995,1194,1293,1723,1863,2082-2083,2086-2087,2095-2096,3128,4321,5050,5190,5222-5223,6679,6697,7771,8000,8008,8080-8081,8090,8118,8123,8181,8300,8443,8888
.''')
            self.fail()
            
        except RuntimeError, e:
            self.assertTrue('"s "' in str(e))

    def test_routers_no_policy(self):
        """
        ensure we can parse a router descriptor which has no p line
        """
        
        self.state._update_network_status('''ns/all=
r fake YkkmgCNRV1/35OPWDvo7+1bmfoo tanLV/4ZfzpYQW0xtGFqAa46foo 2011-12-12 16:29:16 12.45.56.78 443 80
s Exit Fast Guard HSDir Named Running Stable V2Dir Valid FutureProof
w Bandwidth=518000
r PPrivCom012 2CGDscCeHXeV/y1xFrq1EGqj5g4 QX7NVLwx7pwCuk6s8sxB4rdaCKI 2011-12-20 08:34:19 84.19.178.6 9001 0
s Exit Fast Guard HSDir Named Running Stable V2Dir Valid FutureProof
w Bandwidth=518000
p accept 43,53,79-81,110,143,194,220,443,953,989-990,993,995,1194,1293,1723,1863,2082-2083,2086-2087,2095-2096,3128,4321,5050,5190,5222-5223,6679,6697,7771,8000,8008,8080-8081,8090,8118,8123,8181,8300,8443,8888
.''')
        self.assertTrue('fake' in self.state.routers.keys())
        self.assertTrue('PPrivCom012' in self.state.routers.keys())


    def test_routers_no_bandwidth(self):
        """
        ensure we can parse a router descriptor which has no w line
        """
        
        self.state._update_network_status('''ns/all=
r fake YkkmgCNRV1/35OPWDvo7+1bmfoo tanLV/4ZfzpYQW0xtGFqAa46foo 2011-12-12 16:29:16 12.45.56.78 443 80
s Exit Fast Guard HSDir Named Running Stable V2Dir Valid FutureProof
r PPrivCom012 2CGDscCeHXeV/y1xFrq1EGqj5g4 QX7NVLwx7pwCuk6s8sxB4rdaCKI 2011-12-20 08:34:19 84.19.178.6 9001 0
s Exit Fast Guard HSDir Named Running Stable V2Dir Valid FutureProof
w Bandwidth=518000
p accept 43,53,79-81,110,143,194,220,443,953,989-990,993,995,1194,1293,1723,1863,2082-2083,2086-2087,2095-2096,3128,4321,5050,5190,5222-5223,6679,6697,7771,8000,8008,8080-8081,8090,8118,8123,8181,8300,8443,8888
.''')
        self.assertTrue('fake' in self.state.routers.keys())
        self.assertTrue('PPrivCom012' in self.state.routers.keys())

    def test_router_factory(self):
        self.state._update_network_status('''ns/all=
r fake YkkmgCNRV1/35OPWDvo7+1bmfoo tanLV/4ZfzpYQW0xtGFqAa46foo 2011-12-12 16:29:16 12.45.56.78 443 80
s Exit Fast Guard HSDir Named Running Stable V2Dir Valid FutureProof
w Bandwidth=518000
p accept 43,53,79-81,110,143,194,220,443,953,989-990,993,995,1194,1293,1723,1863,2082-2083,2086-2087,2095-2096,3128,4321,5050,5190,5222-5223,6679,6697,7771,8000,8008,8080-8081,8090,8118,8123,8181,8300,8443,8888
r fake YxxmgCNRV1/35OPWDvo7+1bmfoo tanLV/4ZfzpYQW0xtGFqAa46foo 2011-12-12 16:29:16 12.45.56.78 443 80
s Exit Fast Guard HSDir Named Running Stable V2Dir Valid FutureProof
w Bandwidth=543000
p accept 43,53
.''')
        self.assertTrue(self.state.routers.has_key('$624926802351575FF7E4E3D60EFA3BFB56E67E8A'))
        r = self.state.routers['$624926802351575FF7E4E3D60EFA3BFB56E67E8A']
        self.assertEqual(r.controller, self.state.protocol)
        self.assertEqual(r.bandwidth, 518000)
        self.assertEqual(len(self.state.routers_by_name['fake']), 2)

        ## now we do an update
        self.state._update_network_status('''ns/all=
r fake YkkmgCNRV1/35OPWDvo7+1bmfoo tanLV/4ZfzpYQW0xtGFqAa46foo 2011-12-12 16:29:16 12.45.56.78 443 80
s Exit Fast Guard HSDir Named Running Stable V2Dir Valid FutureProof Authority
w Bandwidth=543000
p accept 43,53,79-81,110,143,194,220,443,953,989-990,993,995,1194,1293,1723,1863,2082-2083,2086-2087,2095-2096,3128,4321,5050,5190,5222-5223,6679,6697,7771,8000,8008,8080-8081,8090,8118,8123,8181,8300,8443,8888
.''')
        self.assertEqual(r.bandwidth, 543000)

    def test_empty_stream_update(self):
        self.state._stream_update('''stream-status=''')

    def test_addrmap(self):
        self.state._addr_map('example.com 127.0.0.1 "2012-01-01 00:00:00" EXPIRES=NEVER')

    def test_double_newconsensus(self):
        """
        The arrival of a second NEWCONSENSUS event causes parsing
        errors.
        """

        ## bootstrap the TorState so we can send it a "real" 650
        ## update
        
        self.protocol._set_valid_events(' '.join(self.state.event_map.keys()))
        self.state._bootstrap()

        self.send("250+ns/all=")
        self.send(".")
        self.send("250 OK")

        self.send("250+circuit-status=")
        self.send(".")
        self.send("250 OK")

        self.send("250-stream-status=")
        self.send("250 OK")

        self.send("250-address-mappings/all=")
        self.send('250 OK')

        for ignored in self.state.event_map.items():
            self.send("250 OK")

        self.send("250-entry-guards=")
        self.send("250 OK")

        self.send("250 OK")

        ## state is now bootstrapped, we can send our NEWCONSENSUS update

        self.protocol.dataReceived('\r\n'.join('''650+NEWCONSENSUS
r Unnamed ABJlguUFz1lvQS0jq8nhTdRiXEk /zIVUg1tKMUeyUBoyimzorbQN9E 2012-05-23 01:10:22 219.94.255.254 9001 0
s Fast Guard Running Stable Valid
w Bandwidth=166
p reject 1-65535
.
650 OK
'''.split('\n')))

        self.protocol.dataReceived('\r\n'.join('''650+NEWCONSENSUS
r Unnamed ABJlguUFz1lvQS0jq8nhTdRiXEk /zIVUg1tKMUeyUBoyimzorbQN9E 2012-05-23 01:10:22 219.94.255.254 9001 0
s Fast Guard Running Stable Valid
w Bandwidth=166
p reject 1-65535
.
650 OK
'''.split('\n')))

        self.assertTrue(self.state.routers.has_key('Unnamed'))
        self.assertTrue(self.state.routers.has_key('$00126582E505CF596F412D23ABC9E14DD4625C49'))

    def test_NEWCONSENSUS_ends_with_OK_on_w(self):
        """
        The arrival of a second NEWCONSENSUS event causes parsing
        errors.
        """

        ## bootstrap the TorState so we can send it a "real" 650
        ## update
        
        self.protocol._set_valid_events(' '.join(self.state.event_map.keys()))
        self.state._bootstrap()

        self.send("250+ns/all=")
        self.send(".")
        self.send("250 OK")

        self.send("250+circuit-status=")
        self.send(".")
        self.send("250 OK")

        self.send("250-stream-status=")
        self.send("250 OK")

        self.send("250-address-mappings/all=")
        self.send('250 OK')

        for ignored in self.state.event_map.items():
            self.send("250 OK")

        self.send("250-entry-guards=")
        self.send("250 OK")

        self.send("250 OK")

        ## state is now bootstrapped, we can send our NEWCONSENSUS update

        self.protocol.dataReceived('\r\n'.join('''650+NEWCONSENSUS
r Unnamed ABJlguUFz1lvQS0jq8nhTdRiXEk /zIVUg1tKMUeyUBoyimzorbQN9E 2012-05-23 01:10:22 219.94.255.254 9001 0
s Fast Guard Running Stable Valid
w Bandwidth=166
.
650 OK
'''.split('\n')))

        self.assertTrue(self.state.routers.has_key('Unnamed'))
        self.assertTrue(self.state.routers.has_key('$00126582E505CF596F412D23ABC9E14DD4625C49'))

    def test_NEWCONSENSUS_ends_with_OK_on_s(self):
        """
        The arrival of a second NEWCONSENSUS event causes parsing
        errors.
        """

        ## bootstrap the TorState so we can send it a "real" 650
        ## update
        
        self.protocol._set_valid_events(' '.join(self.state.event_map.keys()))
        self.state._bootstrap()

        self.send("250+ns/all=")
        self.send(".")
        self.send("250 OK")

        self.send("250+circuit-status=")
        self.send(".")
        self.send("250 OK")

        self.send("250-stream-status=")
        self.send("250 OK")

        self.send("250-address-mappings/all=")
        self.send('250 OK')

        for ignored in self.state.event_map.items():
            self.send("250 OK")

        self.send("250-entry-guards=")
        self.send("250 OK")

        self.send("250 OK")

        ## state is now bootstrapped, we can send our NEWCONSENSUS update

        self.protocol.dataReceived('\r\n'.join('''650+NEWCONSENSUS
r Unnamed ABJlguUFz1lvQS0jq8nhTdRiXEk /zIVUg1tKMUeyUBoyimzorbQN9E 2012-05-23 01:10:22 219.94.255.254 9001 0
s Fast Guard Running Stable Valid
.
650 OK
'''.split('\n')))

        self.assertTrue(self.state.routers.has_key('Unnamed'))
        self.assertTrue(self.state.routers.has_key('$00126582E505CF596F412D23ABC9E14DD4625C49'))

    def test_newdesc_parse(self):
        """
        should this mostly go in test_router instead? all we need to
        confirm about the TorState class is that it sends the right
        GETINFO. Well, we're also testing the args get split up
        properly and so forth.
        """
        self.state._newdesc_update("$624926802351575FF7E4E3D60EFA3BFB56E67E8A=fake CLOSED REASON=IOERROR")
        
        # TorState should issue "GETINFO ns/id/624926802351575FF7E4E3D60EFA3BFB56E67E8A"
        # because it hasn't seen this yet, and we'll answer to see if it updates properly
        d = self.protocol.defer
        d.addCallback(self.confirm_router_state)
        self.send("250+ns/id/624926802351575FF7E4E3D60EFA3BFB56E67E8A=")
        self.send("r fake YkkmgCNRV1/35OPWDvo7+1bmfoo tanLV/4ZfzpYQW0xtGFqAa46foo 2011-12-12 16:29:16 12.45.56.78 443 80")
        self.send("s Exit Fast Guard HSDir Named Running Stable V2Dir Valid FutureProof")
        self.send("w Bandwidth=518000")
        self.send("p accept 43,53,79-81,110,143,194,220,443,953,989-990,993,995,1194,1293,1723,1863,2082-2083,2086-2087,2095-2096,3128,4321,5050,5190,5222-5223,6679,6697,7771,8000,8008,8080-8081,8090,8118,8123,8181,8300,8443,8888")
        self.send(".")
        self.send("250 OK")

        return d
    
    def test_stream_create(self):
        self.state._stream_update('1610 NEW 0 1.2.3.4:56')
        self.assertTrue(self.state.streams.has_key(1610))

    def test_stream_destroy(self):
        self.state._stream_update('1610 NEW 0 1.2.3.4:56')
        self.assertTrue(self.state.streams.has_key(1610))
        self.state._stream_update("1610 FAILED 0 www.example.com:0 REASON=DONE REMOTE_REASON=FAILED")
        self.assertTrue(not self.state.streams.has_key(1610))

    def test_stream_detach(self):
        circ = FakeCircuit(1)
        circ.state = 'BUILT'
        self.state.circuits[1] = circ
        
        self.state._stream_update('1610 NEW 0 1.2.3.4:56')
        self.assertTrue(self.state.streams.has_key(1610))
        self.state._stream_update("1610 SUCCEEDED 1 4.3.2.1:80")
        self.assertEqual(self.state.streams[1610].circuit, circ)
        
        self.state._stream_update("1610 DETACHED 0 www.example.com:0 REASON=DONE REMOTE_REASON=FAILED")
        self.assertEqual(self.state.streams[1610].circuit, None)

    def test_stream_listener(self):
        self.protocol._set_valid_events('CIRC STREAM ORCONN BW DEBUG INFO NOTICE WARN ERR NEWDESC ADDRMAP AUTHDIR_NEWDESCS DESCCHANGED NS STATUS_GENERAL STATUS_CLIENT STATUS_SERVER GUARD STREAM_BW CLIENTS_SEEN NEWCONSENSUS BUILDTIMEOUT_SET')
        self.state._add_events()
        for ignored in self.state.event_map.items():
            self.send("250 OK")

        expected = [('new', {}),
                    ]
        listen = StreamListener(expected)
        self.send("650 STREAM 77 NEW 0 www.yahoo.cn:80 SOURCE_ADDR=127.0.0.1:54315 PURPOSE=USER")
        self.state.add_stream_listener(listen)

        self.assertTrue(listen in self.state.streams.values()[0].listeners)
        self.assertEqual(len(self.state.streams), 1)
        self.assertEqual(len(listen.expected), 1)

        self.send("650 STREAM 78 NEW 0 www.yahoo.cn:80 SOURCE_ADDR=127.0.0.1:54315 PURPOSE=USER")
        self.assertEqual(len(self.state.streams), 2)
        self.assertEqual(len(listen.expected), 0)
        
    def test_build_circuit(self):
        class FakeRouter:
            def __init__(self, i):
                self.id_hex = i
                self.flags = []

        path = []
        for x in range(3):
            path.append(FakeRouter("$%040d"%x))
        ## can't just check flags for guard status, need to know if
        ## it's in the running Tor's notion of Entry Guards
        path[0].flags = ['guard']

        self.state.build_circuit(path)
        self.assertEqual(self.transport.value(), 'EXTENDCIRCUIT 0 0000000000000000000000000000000000000000,0000000000000000000000000000000000000001,0000000000000000000000000000000000000002\r\n')
        ## should have gotten a warning about this not being an entry
        ## guard
        self.assertEqual(len(self.flushWarnings()), 1)

    def circuit_callback(self, circ):
        self.assertTrue(isinstance(circ, Circuit))
        self.assertEqual(circ.id, 1234)

    def test_build_circuit_final_callback(self):
        class FakeRouter:
            def __init__(self, i):
                self.id_hex = i
                self.flags = []

        path = []
        for x in range(3):
            path.append(FakeRouter("$%040d"%x))
        ## can't just check flags for guard status, need to know if
        ## it's in the running Tor's notion of Entry Guards
        path[0].flags = ['guard']

        ## FIXME TODO we should verify we get a circuit_new event for
        ## this circuit

        d = self.state.build_circuit(path)
        d.addCallback(self.circuit_callback)
        self.assertEqual(self.transport.value(), 'EXTENDCIRCUIT 0 0000000000000000000000000000000000000000,0000000000000000000000000000000000000001,0000000000000000000000000000000000000002\r\n')
        self.send('250 EXTENDED 1234')
        ## should have gotten a warning about this not being an entry
        ## guard
        self.assertEqual(len(self.flushWarnings()), 1)
        return d

    def test_build_circuit_error(self):
        """
        tests that we check the callback properly
        """

        try:
            self.state._find_circuit_after_extend("FOO 1234")
            self.assertTrue(False)
        except RuntimeError, e:
            self.assertTrue('Expected EXTENDED' in str(e))

    def test_listener_mixins(self):
        smi = StreamListenerMixin
        self.assertTrue(verifyClass(IStreamListener, StreamListenerMixin))
        self.assertTrue(verifyClass(ICircuitListener, CircuitListenerMixin))
