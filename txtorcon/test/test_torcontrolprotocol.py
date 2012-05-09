
from zope.interface import implements
from twisted.python import log
from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.internet import reactor, defer
from twisted.internet.protocol import Factory
from twisted.internet.endpoints import TCP4ClientEndpoint, TCP4ServerEndpoint
from twisted.protocols.basic import LineReceiver
from txtorcon import TorControlProtocol, TorProtocolFactory, TorState, IStreamAttacher, ICircuitListener, IStreamListener
from txtorcon.torcontrolprotocol import parse_keywords, DEFAULT_VALUE

import types
import functools

def do_nothing(*args):
    pass

class CallbackChecker:
    def __init__(self, expected):
        self.expected_value = expected
        self.called_back = False
        
    def __call__(self, *args, **kwargs):
        v = args[0]
        if v != self.expected_value:
            print "WRONG"
            raise RuntimeError('Expected "%s" but got "%s"' % (self.expected_value, v))
        ##print "got correct value",v
        self.called_back = True
        return v

class LogicTests(unittest.TestCase):

    def setUp(self):
        self.protocol = TorControlProtocol()
        self.protocol.connectionMade = do_nothing
        self.transport = proto_helpers.StringTransport()
        self.protocol.makeConnection(self.transport)

    def test_set_conf_wrong_args(self):
        ctl = TorControlProtocol()
        d = ctl.set_conf('a')
        self.assertTrue(d.called)
        self.assertTrue(d.result)
        self.assertTrue('even number' in d.result.getErrorMessage())
        ## ignore the error so trial doesn't get unhappy
        d.addErrback(lambda foo: True)
        return d

class FactoryTests(unittest.TestCase):
    def test_create(self):
        TorProtocolFactory().buildProtocol(None)
      
class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.protocol = TorControlProtocol()
        self.transport = proto_helpers.StringTransport()

    def send(self, line):
        self.protocol.dataReceived(line.strip() + "\r\n")
        
    def test_authenticate_cookie(self):
        self.protocol.makeConnection(self.transport)
        self.assertTrue(self.transport.value() == 'PROTOCOLINFO 1\r\n')
        self.transport.clear()
        cookie_data = 'cookiedata!cookiedata!cookiedata'
        open('authcookie', 'w').write(cookie_data)
        self.send('250-PROTOCOLINFO 1')
        self.send('250-AUTH METHODS=COOKIE,HASHEDPASSWORD COOKIEFILE="authcookie"')
        self.send('250-VERSION Tor="0.2.2.34"')
        self.send('250 OK')

        self.assertTrue(self.transport.value() == 'AUTHENTICATE %s\r\n' % cookie_data.encode("hex"))

    def test_authenticate_password(self):
        self.protocol.password = 'foo'
        self.protocol.makeConnection(self.transport)
        self.assertTrue(self.transport.value() == 'PROTOCOLINFO 1\r\n')
        self.transport.clear()
        self.send('250-PROTOCOLINFO 1')
        self.send('250-AUTH METHODS=HASHEDPASSWORD')
        self.send('250-VERSION Tor="0.2.2.34"')
        self.send('250 OK')

        self.assertTrue(self.transport.value() == 'AUTHENTICATE %s\r\n' % "foo".encode("hex"))

    def confirmAuthFailed(self, *args):
        self.auth_failed = True
        
    def test_authenticate_no_password(self):
        self.protocol._auth_failed = self.confirmAuthFailed
        self.auth_failed = False
        
        self.protocol.makeConnection(self.transport)
        self.assertTrue(self.transport.value() == 'PROTOCOLINFO 1\r\n')
        
        self.send('250-PROTOCOLINFO 1')
        self.send('250-AUTH METHODS=HASHEDPASSWORD')
        self.send('250-VERSION Tor="0.2.2.34"')
        self.send('250 OK')

        self.assertTrue(self.auth_failed)

class ProtocolTests(unittest.TestCase):

    def setUp(self):
        self.protocol = TorControlProtocol()
        self.protocol.connectionMade = do_nothing
        self.transport = proto_helpers.StringTransport()
        self.protocol.makeConnection(self.transport)

    def tearDown(self):
        self.protocol = None

    def send(self, line):
        self.protocol.dataReceived(line.strip() + "\r\n")

    def test_statemachine_broadcast_no_code(self):
        try:
            self.protocol._broadcast_response("foo")
            self.fail()
        except RuntimeError, e:
            self.assertTrue('No code set yet' in e.message)

    def test_statemachine_broadcast_unknown_code(self):
        try:
            self.protocol.code = 999
            self.protocol._broadcast_response("foo")
            self.fail()
        except RuntimeError, e:
            self.assertTrue('Unknown code' in e.message)

    def test_statemachine_is_finish(self):
        self.assertTrue(not self.protocol._is_finish_line(''))
        self.assertTrue(self.protocol._is_finish_line('.'))
        self.assertTrue(self.protocol._is_finish_line('300 '))
        self.assertTrue(not self.protocol._is_finish_line('250-'))

    def test_statemachine_singleline(self):
        self.assertTrue(not self.protocol._is_single_line_response('foo'))

    def test_statemachine_continuation(self):
        try:
            self.protocol.code = 250
            self.protocol._is_continuation_line("123 ")
            self.fail()
        except RuntimeError, e:
            self.assertTrue('Unexpected code' in e.message)

    def test_statemachine_multiline(self):
        try:
            self.protocol.code = 250
            self.protocol._is_multi_line("123 ")
            self.fail()
        except RuntimeError, e:
            self.assertTrue('Unexpected code' in e.message)

    def auth_failed(self, msg):
        self.assertTrue(str(msg.value) == '551 go away')
        self.got_auth_failed = True

    def test_authenticate_fail(self):
        self.got_auth_failed = False
        self.protocol._auth_failed = self.auth_failed

        self.protocol.password='foo'
        self.protocol._do_authenticate('''PROTOCOLINFO 1
AUTH METHODS=HASHEDPASSWORD
VERSION Tor="0.2.2.35"
OK''')
        self.send('551 go away\r\n')
        self.assertTrue(self.got_auth_failed)

    def confirm_version_events(self, arg):
        self.assertTrue(self.protocol.version == 'foo')
        events = 'GUARD STREAM CIRC NS NEWCONSENSUS ORCONN NEWDESC ADDRMAP STATUS_GENERAL'.split()
        self.assertTrue(len(self.protocol.valid_events) == len(events))
        [self.assertTrue(self.protocol.valid_events.has_key(x)) for x in events]
            
    def test_bootstrap_callback(self):
        d = self.protocol.post_bootstrap
        d.addCallback(CallbackChecker(self.protocol))
        d.addCallback(self.confirm_version_events)
        
        events = 'GUARD STREAM CIRC NS NEWCONSENSUS ORCONN NEWDESC ADDRMAP STATUS_GENERAL'
        self.protocol._bootstrap()

        ## answer all the requests generated by boostrapping etc.
        self.send("250-version=foo")
        self.send("250 OK")

        self.send("250-events/names=" + events)
        self.send("250 OK")
        
        self.send("250 OK")             # for USEFEATURE

        return d


    def test_async(self):
        ## test the example from control-spec.txt to see that we
        ## handle interleaved async notifications properly.
        self.protocol._set_valid_events('CIRC')
        self.protocol.add_event_listener('CIRC', do_nothing)
        self.send("250 OK")
        
        d = self.protocol.get_conf("SOCKSPORT ORPORT")
        self.send("650 CIRC 1000 EXTENDED moria1,moria2")
        self.send("250-SOCKSPORT=9050")
        self.send("250 ORPORT=0")
        return d

    def test_async_multiline(self):
        ## same as above, but i think the 650's can be multline,
        ## too. Like:
        ## 650-CIRC 1000 EXTENDED moria1,moria2 0xBEEF
        ## 650-EXTRAMAGIC=99
        ## 650 ANONYMITY=high

        self.protocol._set_valid_events('CIRC')
        self.protocol.add_event_listener('CIRC', CallbackChecker("1000 EXTENDED moria1,moria2\nEXTRAMAGIC=99\nANONYMITY=high"))
        self.send("250 OK")
        
        d = self.protocol.get_conf("SOCKSPORT ORPORT")
        d.addCallback(CallbackChecker({"ORPORT":"0", "SOCKSPORT":"9050"}))
        self.send("650-CIRC 1000 EXTENDED moria1,moria2")
        self.send("650-EXTRAMAGIC=99")
        self.send("650 ANONYMITY=high")
        self.send("250-SOCKSPORT=9050")
        self.send("250 ORPORT=0")
        return d

    def test_multiline_plus(self):
        """
        """

        d = self.protocol.get_info("FOO")
        d.addCallback(CallbackChecker({"FOO":"\na\nb\nc"}))
        self.send("250+FOO=")
        self.send("a")
        self.send("b")
        self.send("c")
        self.send(".")
        self.send("250 OK")
        return d

    def incremental_check(self, expected, actual):
        if '=' in actual or actual == 'OK':
            return
        self.assertTrue(expected == actual)

    def test_getinfo_incremental(self):
        d = self.protocol.get_info_incremental("FOO", functools.partial(self.incremental_check, "bar"))
        self.send("250+FOO=")
        self.send("bar")
        self.send("bar")
        self.send(".")
        self.send("250 OK")
        return d        

    def test_getinfo_incremental_continuation(self):
        d = self.protocol.get_info_incremental("FOO", functools.partial(self.incremental_check, "bar"))
        self.send("250-FOO=")
        self.send("250-bar")
        self.send("250-bar")
        self.send("250 OK")
        return d        

    def test_getconf(self):
        d = self.protocol.get_conf("SOCKSPORT ORPORT")
        d.addCallback(CallbackChecker({'SocksPort':'9050',
                                       'ORPort':'0'}))
        self.send("250-SocksPort=9050")
        self.send("250 ORPort=0")
        return d

    def test_getconf_raw(self):
        d = self.protocol.get_conf_raw("SOCKSPORT ORPORT")
        d.addCallback(CallbackChecker('SocksPort=9050\nORPort=0'))
        self.send("250-SocksPort=9050")
        self.send("250 ORPort=0")
        return d

    def response_ok(self, v):
        self.assertTrue(v == 'OK')

    def test_setconf(self):
        d = self.protocol.set_conf("foo", "bar").addCallback(functools.partial(self.response_ok))
        self.send("250 OK")
        self._wait(d)
        self.assertTrue(self.transport.value() == "SETCONF foo=bar\r\n")

    def test_setconf_with_space(self):
        d = self.protocol.set_conf("foo", "a value with a space").addCallback(functools.partial(self.response_ok))
        self.send("250 OK")
        self._wait(d)
        self.assertTrue(self.transport.value() == 'SETCONF foo="a value with a space"\r\n')

    def test_setconf_multi(self):
        d = self.protocol.set_conf("foo", "bar", "baz", 1)
        self.send("250 OK")
        self._wait(d)
        self.assertTrue(self.transport.value() == "SETCONF foo=bar baz=1\r\n")

    def error(self, failure):
        print "ERROR",failure
        self.assertTrue(False)

    def test_twocommands(self):
        "Two commands on the wire before first response."
        d1 = self.protocol.get_conf("FOO")
        ht = {"a": "one", "b": "two"}
        d1.addCallback(CallbackChecker(ht)).addErrback(log.err)

        d2 = self.protocol.get_info_raw("BAR")
        d2.addCallback(CallbackChecker("bar")).addErrback(log.err)

        self.send("250-a=one")
        self.send("250-b=two")
        self.send("250 OK")
        self.send("250 bar")

        return d2

    def test_signal_error(self):
        try:
            self.protocol.signal('FOO')
            self.fail()
        except Exception, e:
            self.assertTrue('Invalid signal' in e.message)

    def test_signal(self):
        self.protocol.valid_signals = ['NEWNYM']
        self.protocol.signal('NEWNYM')
        self.assertTrue(self.transport.value() == 'SIGNAL NEWNYM\r\n')

    def test_notify_after_getinfo(self):
        self.protocol._set_valid_events('CIRC')
        self.protocol.add_event_listener('CIRC', CallbackChecker("1000 EXTENDED moria1,moria2"))
        self.send("250 OK")
        
        d = self.protocol.get_info("FOO")
        d.addCallback(CallbackChecker({'a':'one'})).addErrback(self.fail)
        self.send("250-a=one")
        self.send("250 OK")
        self.send("650 CIRC 1000 EXTENDED moria1,moria2")
        return d

    def test_notify_error(self):
        self.protocol._set_valid_events('CIRC')

        try:
            self.send("650 CIRC 1000 EXTENDED moria1,moria2")
            self.assertTrue(False)
        except Exception, e:
            self.assertTrue("Wasn't listening" in e.message )

    def test_getinfo(self):
        d = self.protocol.get_info("version")
        d.addCallback(CallbackChecker({'version':'0.2.2.34'}))
        d.addErrback(self.fail)
        
        self.send("250-version=0.2.2.34")
        self.send("250 OK")

        self.assertTrue(self.transport.value() == "GETINFO version\r\n")
        return d

    def test_addevent(self):
        self.protocol._set_valid_events('FOO BAR')
        
        self.protocol.add_event_listener('FOO', do_nothing)
        ## is it dangerous/ill-advised to depend on internal state of
        ## class under test?
        d = self.protocol.defer
        self.send("250 OK")
        self._wait(d)
        self.assertTrue(self.transport.value().split('\r\n')[-2] == "SETEVENTS FOO")
        self.transport.clear()

        self.protocol.add_event_listener('BAR', do_nothing)
        d = self.protocol.defer
        self.send("250 OK")
        self.assertTrue(self.transport.value() == "SETEVENTS FOO BAR\r\n" or \
                        self.transport.value() == "SETEVENTS BAR FOO\r\n")
        self._wait(d)

        try:
            self.protocol.add_event_listener('SOMETHING_INVALID', do_nothing)
            self.assertTrue(False)
        except:
            pass

    def test_eventlistener(self):
        self.protocol._set_valid_events('STREAM')
        class EventListener(object):
            stream_events = 0
            def __call__(self, data):
                self.stream_events += 1
        listener = EventListener()
        evt = self.protocol.add_event_listener('STREAM', listener)
        
        d = self.protocol.defer
        self.send("250 OK")
        self._wait(d)
        self.send("650 STREAM 1234 NEW 4321 1.2.3.4:555 REASON=MISC")
        self.send("650 STREAM 2345 NEW 4321 2.3.4.5:666 REASON=MISC")
        self.assertTrue(listener.stream_events == 2)

    def test_remove_eventlistener(self):
        self.protocol._set_valid_events('STREAM')
        class EventListener(object):
            stream_events = 0
            def __call__(self, data):
                self.stream_events += 1
        listener = EventListener()
        evt = self.protocol.add_event_listener('STREAM', listener)
        self.assertTrue(self.transport.value() == 'SETEVENTS STREAM\r\n')
        self.protocol.lineReceived("250 OK")
        self.transport.clear()
        self.protocol.remove_event_listener('STREAM', listener)
        self.assertTrue(self.transport.value() == 'SETEVENTS \r\n')

    def test_remove_eventlistener_multiple(self):
        self.protocol._set_valid_events('STREAM')
        class EventListener(object):
            stream_events = 0
            def __call__(self, data):
                self.stream_events += 1
        listener0 = EventListener()
        listener1 = EventListener()
        evt = self.protocol.add_event_listener('STREAM', listener0)
        self.assertTrue(self.transport.value() == 'SETEVENTS STREAM\r\n')
        self.protocol.lineReceived("250 OK")
        self.transport.clear()
        ## add another one, shouldn't issue a tor command
        evt = self.protocol.add_event_listener('STREAM', listener1)
        self.assertTrue(self.transport.value() == '')

        ## remove one, should still not issue a tor command
        self.protocol.remove_event_listener('STREAM', listener0)
        self.assertTrue(self.transport.value() == '')

        ## remove the other one, NOW should issue a command
        self.protocol.remove_event_listener('STREAM', listener1)        
        self.assertTrue(self.transport.value() == 'SETEVENTS \r\n')

        ## try removing invalid event
        try:
            self.protocol.remove_event_listener('FOO', listener0)
            self.fail()
        except Exception, e:
            self.assertTrue('FOO' in e.message)

    def checkContinuation(self, v):
        self.assertTrue(v == "key=\nvalue0\nvalue1\nOK")

    def test_continuationLine(self):
        d = self.protocol.get_info_raw("key")

        d.addCallback(self.checkContinuation)
        
        self.send("250+key=")
        self.send("value0")
        self.send("value1")
        self.send(".")
        self.send("250 OK")

        return d

    def test_newdesc(self):
        """
        FIXME: this test is now maybe a little silly, it's just testing multiline GETINFO...
        (Real test is in TorStateTests.test_newdesc_parse)
        """
        
        self.protocol.get_info_raw('ns/id/624926802351575FF7E4E3D60EFA3BFB56E67E8A')
        d = self.protocol.defer
        d.addCallback(CallbackChecker("""ns/id/624926802351575FF7E4E3D60EFA3BFB56E67E8A=
r fake YkkmgCNRV1/35OPWDvo7+1bmfoo tanLV/4ZfzpYQW0xtGFqAa46foo 2011-12-12 16:29:16 12.45.56.78 443 80
s Exit Fast Guard HSDir Named Running Stable V2Dir Valid
w Bandwidth=518000
p accept 43,53,79-81,110,143,194,220,443,953,989-990,993,995,1194,1293,1723,1863,2082-2083,2086-2087,2095-2096,3128,4321,5050,5190,5222-5223,6679,6697,7771,8000,8008,8080-8081,8090,8118,8123,8181,8300,8443,8888
OK"""))
        
        self.send("250+ns/id/624926802351575FF7E4E3D60EFA3BFB56E67E8A=")
        self.send("r fake YkkmgCNRV1/35OPWDvo7+1bmfoo tanLV/4ZfzpYQW0xtGFqAa46foo 2011-12-12 16:29:16 12.45.56.78 443 80")
        self.send("s Exit Fast Guard HSDir Named Running Stable V2Dir Valid")
        self.send("w Bandwidth=518000")
        self.send("p accept 43,53,79-81,110,143,194,220,443,953,989-990,993,995,1194,1293,1723,1863,2082-2083,2086-2087,2095-2096,3128,4321,5050,5190,5222-5223,6679,6697,7771,8000,8008,8080-8081,8090,8118,8123,8181,8300,8443,8888")
        self.send(".")
        self.send("250 OK")

        return d

class ParseTests(unittest.TestCase):

    def setUp(self):
        self.controller = TorState(TorControlProtocol())
        self.controller.connectionMade = do_nothing
    
    def test_keywords(self):
        x = parse_keywords("""events/names=CIRC STREAM ORCONN BW DEBUG INFO NOTICE WARN ERR NEWDESC ADDRMAP AUTHDIR_NEWDESCS DESCCHANGED NS STATUS_GENERAL STATUS_CLIENT STATUS_SERVER GUARD STREAM_BW CLIENTS_SEEN NEWCONSENSUS BUILDTIMEOUT_SET
OK""")
        self.assertTrue(x.has_key("events/names"))
        self.assertTrue(x['events/names'] == 'CIRC STREAM ORCONN BW DEBUG INFO NOTICE WARN ERR NEWDESC ADDRMAP AUTHDIR_NEWDESCS DESCCHANGED NS STATUS_GENERAL STATUS_CLIENT STATUS_SERVER GUARD STREAM_BW CLIENTS_SEEN NEWCONSENSUS BUILDTIMEOUT_SET')
        self.assertTrue(len(x.keys()) == 1)

    def test_default_keywords(self):
        x = parse_keywords('foo')
        self.assertTrue(len(x) == 1)
        self.assertTrue(x.has_key('foo'))
        self.assertTrue(x['foo'] == DEFAULT_VALUE)

    def test_multientry_keywords_2(self):
        x = parse_keywords('''foo=bar
foo=zarimba''')
        self.assertTrue(len(x) == 1)
        self.assertTrue(isinstance(x['foo'], types.ListType))
        self.assertTrue(len(x['foo']) == 2)
        self.assertTrue(x['foo'][0] == 'bar')
        self.assertTrue(x['foo'][1] == 'zarimba')

    def test_multientry_keywords_3(self):
        x = parse_keywords('''foo=bar
foo=baz
foo=zarimba''')
        self.assertTrue(len(x) == 1)
        self.assertTrue(isinstance(x['foo'], types.ListType))
        self.assertTrue(len(x['foo']) == 3)
        self.assertTrue(x['foo'][0] == 'bar')
        self.assertTrue(x['foo'][1] == 'baz')
        self.assertTrue(x['foo'][2] == 'zarimba')

    def test_multientry_keywords_4(self):
        x = parse_keywords('''foo=bar
foo=baz
foo=zarimba
foo=foo''')
        self.assertTrue(len(x) == 1)
        self.assertTrue(isinstance(x['foo'], types.ListType))
        self.assertTrue(len(x['foo']) == 4)
        self.assertTrue(x['foo'][0] == 'bar')
        self.assertTrue(x['foo'][1] == 'baz')
        self.assertTrue(x['foo'][2] == 'zarimba')
        self.assertTrue(x['foo'][3] == 'foo')

    def test_multiline_keywords(self):
        x = parse_keywords('''foo=bar
baz''')
        self.assertTrue(len(x) == 1)
        self.assertTrue(x.has_key('foo'))
        self.assertTrue(x['foo'] == 'bar\nbaz')

    def test_network_status(self):
        self.controller._update_network_status("""ns/all=
r right2privassy3 ADQ6gCT3DiFHKPDFr3rODBUI8HM JehnjB8l4Js47dyjLCEmE8VJqao 2011-12-02 03:36:40 50.63.8.215 9023 0
s Exit Fast Named Running Stable Valid
w Bandwidth=53
p accept 80,1194,1220,1293,1500,1533,1677,1723,1863,2082-2083,2086-2087,2095-2096,2102-2104,3128,3389,3690,4321,4643,5050,5190,5222-5223,5228,5900,6660-6669,6679,6697,8000,8008,8074,8080,8087-8088,8443,8888,9418,9999-10000,19294,19638
r Unnamed AHe2V2pmj4Yfn0H9+Np3lci7htU T/g7ZLzG/ooqCn+gdLd9Jjh+AEI 2011-12-02 15:52:09 84.101.216.232 443 9030
s Exit Fast Running V2Dir Valid
w Bandwidth=33
p reject 25,119,135-139,445,563,1214,4661-4666,6346-6429,6699,6881-6999""")
        ## the routers list is always keyed with both name and hash
        self.assertTrue(len(self.controller.routers_by_name) == 2)
        self.assertTrue(self.controller.routers.has_key("right2privassy3"))
        self.assertTrue(self.controller.routers.has_key("Unnamed"))

        self.controller.routers.clear()
        self.controller.routers_by_name.clear()

    def test_circuit_status(self):
        self.controller._update_network_status("""ns/all=
r wildnl f+Ty/+B6lgYr0Ntbf67O/L2M8ZI c1iK/kPPXKGZZvwXRWbvL9eCfSc 2011-12-02 19:07:05 209.159.142.164 9001 0
s Exit Fast Named Running Stable Valid
w Bandwidth=1900
p reject 25,119,135-139,445,563,1214,4661-4666,6346-6429,6699,6881-6999
r l0l wYXUpLBpzVWfzVSMgGO0dThdd38 KIJC+W1SHeaFOj/BVsEAgxbtQNM 2011-12-02 13:43:39 94.23.168.39 443 80
s Fast Named Running Stable V2Dir Valid
w Bandwidth=22800
p reject 1-65535
r Tecumseh /xAD0tFLS50Dkz+O37xGyVLoKlk yJHbad7MFl1VW2/23RxrPKBTOIE 2011-12-02 09:44:10 76.73.48.211 22 9030
s Fast Guard HSDir Named Running Stable V2Dir Valid
w Bandwidth=18700
p reject 1-65535""")
        self.controller._circuit_status("""250+circuit-status=
4472 BUILT $FF1003D2D14B4B9D03933F8EDFBC46C952E82A59=Tecumseh,$C185D4A4B069CD559FCD548C8063B475385D777F=l0l,$7FE4F2FFE07A96062BD0DB5B7FAECEFCBD8CF192=wildnl PURPOSE=GENERAL
""")
        self.assertTrue(len(self.controller.circuits) == 1)
        self.assertTrue(self.controller.circuits.has_key(4472))

        self.controller.routers.clear()
        self.controller.routers_by_name.clear()
        self.controller.circuits.clear()
