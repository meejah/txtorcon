import os
import shutil
import tempfile
import functools

from zope.interface import implements
from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.internet import defer, error
from twisted.python.failure import Failure
from twisted.internet.interfaces import IReactorCore, IProtocolFactory, IReactorTCP

from txtorcon import TorControlProtocol, ITorControlProtocol, TorConfig, DEFAULT_VALUE, HiddenService, launch_tor, TCPHiddenServiceEndpoint

from txtorcon.util import delete_file_or_tree

def do_nothing(*args):
    pass

class FakeControlProtocol:
    """
    This is a little weird, but in most tests the answer at the top of
    the list is sent back immediately in an already-called
    Deferred. However, if the answer list is empty at the time of the
    call, instead the returned Deferred is added to the pending list
    and answer_pending() may be called to have the next Deferred
    fire. (see test_slutty_postbootstrap for an example).

    It is done this way in case we need to have some other code run
    between the get_conf (or whatever) and the callback -- if the
    Deferred is already-fired when get_conf runs, there's a Very Good
    Chance (always?) that the callback just runs right away.
    """
    
    implements(ITorControlProtocol)     # actually, just get_info_raw

    def __init__(self, answers):
        self.answers = answers
        self.pending = []
        self.post_bootstrap = defer.succeed(self)
        self.sets = []
        self.events = {}

    def answer_pending(self, answer):
        d = self.pending[0]
        self.pending = self.pending[1:]
        d.callback(answer)

    def get_info_raw(self, info):
        if len(self.answers) == 0:
            d = defer.Deferred()
            self.pending.append(d)
            return d
        
        d = defer.succeed(self.answers[0])
        self.answers = self.answers[1:]
        return d

    def get_conf(self, info):
        if len(self.answers) == 0:
            d = defer.Deferred()
            self.pending.append(d)
            return d
        
        d = defer.succeed(self.answers[0])
        self.answers = self.answers[1:]
        return d

    get_conf_raw = get_conf             # up to test author ensure the answer is a raw string
    
    def set_conf(self, *args):
        for i in range(0, len(args), 2):
            self.sets.append((args[i], args[i+1]))
        return defer.succeed('OK')

    def add_event_listener(self, nm, cb):
        self.events[nm] = cb

class CheckAnswer:
    def __init__(self, test, ans):
        self.answer = ans
        self.test = test

    def __call__(self, x):
        self.test.assertEqual(x, self.answer)

class ConfigTests(unittest.TestCase):
    """
    FIXME hmm, this all seems a little convoluted to test errors? 
    Maybe not that bad.
    """
    
    def setUp(self):
        self.protocol = FakeControlProtocol([])

    def test_boolean_parse_error(self):
        self.protocol.answers.append('''config/names=
foo Boolean
OK''')
        self.protocol.answers.append({'foo':'bar'})
        conf = TorConfig(self.protocol)
        errs = self.flushLoggedErrors(ValueError)
        self.assertEqual(len(errs), 1)
        ## dunno if asserting strings in messages is a good idea...
        self.assertTrue('invalid literal' in errs[0].getErrorMessage())
    
    def test_boolean_parser(self):
        self.protocol.answers.append('''config/names=
foo Boolean
bar Boolean
OK''')
        self.protocol.answers.append({'foo':'0'})
        self.protocol.answers.append({'bar':'1'})
        ## FIXME does a Tor controller only ever send "0" and "1" for
        ## true/false? Or do we need to accept others?
        
        conf = TorConfig(self.protocol)
        self.assertTrue(conf.foo is False)
        self.assertTrue(conf.bar is True)

    def test_boolean_auto_parser(self):
        self.protocol.answers.append('''config/names=
foo Boolean+Auto
bar Boolean+Auto
baz Boolean+Auto
OK''')
        self.protocol.answers.append({'foo':'0'})
        self.protocol.answers.append({'bar':'1'})
        self.protocol.answers.append({'baz':'auto'})

        conf = TorConfig(self.protocol)
        self.assertTrue(conf.foo is 0)
        self.assertTrue(conf.bar is 1)
        self.assertTrue(conf.baz is -1)

    def test_string_parser(self):
        self.protocol.answers.append('''config/names=
foo String
OK''')
        self.protocol.answers.append({'foo':'bar'})
        conf = TorConfig(self.protocol)
        self.assertEqual(conf.foo, 'bar')        

    def test_int_parser(self):
        self.protocol.answers.append('''config/names=
foo Integer
OK''')
        self.protocol.answers.append({'foo':'123'})
        conf = TorConfig(self.protocol)
        self.assertEqual(conf.foo, 123)
        
    def test_int_parser_error(self):
        self.protocol.answers.append('''config/names=
foo Integer
OK''')
        self.protocol.answers.append({'foo':'123foo'})
        conf = TorConfig(self.protocol)
        errs = self.flushLoggedErrors(ValueError)
        self.assertEqual(len(errs), 1)
        self.assertTrue(isinstance(errs[0].value, ValueError))

    def test_int_parser_error_2(self):
        self.protocol.answers.append('''config/names=
foo Integer
OK''')
        self.protocol.answers.append({'foo':'1.23'})
        conf = TorConfig(self.protocol)
        errs = self.flushLoggedErrors(ValueError)
        self.assertEqual(len(errs), 1)
        self.assertTrue(isinstance(errs[0].value, ValueError))

    def test_linelist_parser(self):
        self.protocol.answers.append('''config/names=
foo LineList
OK''')
        self.protocol.answers.append({'foo':'bar\nbaz'})
        conf = TorConfig(self.protocol)
        self.assertEqual(conf.foo, ['bar', 'baz'])

    def test_listlist_parser_with_list(self):
        self.protocol.answers.append('config/names=\nfoo LineList\nOK')
        self.protocol.answers.append({'foo': [1,2,3]})
        
        conf = TorConfig(self.protocol)
        self.assertEqual(conf.foo, ['1', '2', '3'])

    def test_float_parser(self):
        self.protocol.answers.append('''config/names=
foo Float
OK''')
        self.protocol.answers.append({'foo':'1.23'})
        conf = TorConfig(self.protocol)
        self.assertEqual(conf.foo, 1.23)

    def test_float_parser_error(self):
        self.protocol.answers.append('''config/names=
foo Float
OK''')
        self.protocol.answers.append({'foo':'1.23fff'})
        conf = TorConfig(self.protocol)
        errs = self.flushLoggedErrors(ValueError)
        self.assertEqual(len(errs), 1)
        self.assertTrue(isinstance(errs[0].value, ValueError))

    def test_list(self):
        self.protocol.answers.append('''config/names=
bing CommaList
OK''')
        self.protocol.answers.append({'bing':'foo,bar,baz'})
        conf = TorConfig(self.protocol)
        self.assertEqual(conf.config['bing'], ['foo','bar','baz'])
#        self.assertEqual(conf.bing, ['foo','bar','baz'])
        
    def test_single_list(self):
        self.protocol.answers.append('''config/names=
bing CommaList
OK''')
        self.protocol.answers.append({'bing':'foo'})
        conf = TorConfig(self.protocol)
        self.assertEqual(conf.config['bing'], ['foo'])

    def test_multi_list_space(self):
        self.protocol.answers.append('''config/names=
bing CommaList
OK''')
        self.protocol.answers.append({'bing':'foo, bar , baz'})
        conf = TorConfig(self.protocol)
        self.assertEqual(conf.bing, ['foo', 'bar', 'baz'])

    def test_descriptor_access(self):
        self.protocol.answers.append('''config/names=
bing CommaList
OK''')
        self.protocol.answers.append({'bing':'foo,bar'})
        
        conf = TorConfig(self.protocol)
        self.assertEqual(conf.config['bing'], ['foo','bar'])
        self.assertEqual(conf.bing, ['foo','bar'])

        self.protocol.answers.append('250 OK')
        conf.bing = ['a','b']
        self.assertEqual(conf.bing, ['foo','bar'])
        
        d = conf.save()
        def confirm(conf):
            self.assertEqual(conf.config['bing'], ['a','b'])
            self.assertEqual(conf.bing, ['a','b'])
        d.addCallbacks(confirm, self.fail)
        return d

    def test_unknown_descriptor(self):
        self.protocol.answers.append('''config/names=
bing CommaList
OK''')
        self.protocol.answers.append({'bing':'foo'})
        
        conf = TorConfig(self.protocol)
        try:
            conf.foo
            self.assertTrue(False)
        except KeyError, e:
            self.assertTrue('foo' in str(e))
            
    def test_invalid_parser(self):
        self.protocol.answers.append('''config/names=
SomethingExciting NonExistantParserType
OK''')
        conf = TorConfig(self.protocol)
        errs = self.flushLoggedErrors()
        self.assertEqual(len(errs), 1)
        self.assertTrue('NonExistantParserType' in str(errs[0]))

    def foo(self, *args):
        print "FOOO",args

    def test_slutty_postbootstrap(self):
        # test that doPostbootstrap still works in "slutty" mode
        self.protocol.answers.append('''config/names=
ORPort Port
OK''')
        ## we can't answer right away, or we do all the _do_setup
        ## callbacks before _setup_ is set -- but we need to do an
        ## answer callback after that to trigger this bug

        conf = TorConfig(self.protocol)
        self.assertTrue(conf.__dict__.has_key('_setup_'))
        self.protocol.answer_pending({'ORPort':1})

    def test_immediate_bootstrap(self):
        self.protocol.post_bootstrap = None
        self.protocol.answers.append('''config/names=
foo Boolean
OK''')
        self.protocol.answers.append({'foo':'0'})
        conf = TorConfig(self.protocol)
        self.assertTrue(conf.config.has_key('foo'))

    def test_multiple_orports(self):
        self.protocol.post_bootstrap = None
        self.protocol.answers.append('''config/names=
OrPort CommaList
OK''')
        self.protocol.answers.append({'OrPort':'1234'})
        conf = TorConfig(self.protocol)
        conf.OrPort = ['1234', '4321']
        conf.save()
        self.assertEqual(self.protocol.sets, [('OrPort', '1234'),
                                              ('OrPort', '4321')])

    def test_set_multiple(self):
        self.protocol.answers.append('''config/names=
AwesomeKey String
OK''')
        self.protocol.answers.append({'AwesomeKey':'foo'})
        
        conf = TorConfig(self.protocol)
        conf.awesomekey
        conf.awesomekey = 'baz'
        self.assertTrue(conf.needs_save())
        conf.awesomekey = 'nybble'
        conf.awesomekey = 'pac man'

        conf.save()
        
        self.assertEqual(len(self.protocol.sets), 1)
        self.assertEqual(self.protocol.sets[0], ('AwesomeKey', 'pac man'))

    def test_log_double_save(self):
        self.protocol.answers.append('''config/names=
Log LineList
Foo String
OK''')
        self.protocol.answers.append({'Log':'notice file /var/log/tor/notices.log'})
        self.protocol.answers.append({'Foo':'foo'})
        conf = TorConfig(self.protocol)

        conf.log.append('info file /tmp/foo.log')
        conf.foo = 'bar'
        self.assertTrue(conf.needs_save())
        conf.save()
        conf.save()                     # just for the code coverage...
        
        self.assertTrue(not conf.needs_save())
        self.protocol.sets = []
        conf.save()
        self.assertEqual(self.protocol.sets, [])

    def test_set_save_modify(self):
        self.protocol.answers.append('''config/names=
Log LineList
OK''')
        self.protocol.answers.append({'Log':'notice file /var/log/tor/notices.log'})
        conf = TorConfig(self.protocol)

        conf.log = []
        self.assertTrue(conf.needs_save())
        conf.save()

        conf.log.append('notice file /tmp/foo.log')
        self.assertTrue(conf.needs_save())

    def test_proper_sets(self):
        self.protocol.answers.append('''config/names=
Log LineList
OK''')
        self.protocol.answers.append({'Log':'foo'})
        
        conf = TorConfig(self.protocol)
        conf.log.append('bar')
        conf.save()

        self.assertEqual(len(self.protocol.sets), 2)
        self.assertEqual(self.protocol.sets[0], ('Log', 'foo'))
        self.assertEqual(self.protocol.sets[1], ('Log', 'bar'))
        
class LogTests(unittest.TestCase):
    
    def setUp(self):
        self.protocol = FakeControlProtocol([])
        self.protocol.answers.append('''config/names=
Log LineList
OK''')
        self.protocol.answers.append({'Log':'notice file /var/log/tor/notices.log'})

    def test_log_set(self):
        conf = TorConfig(self.protocol)

        conf.log.append('info file /tmp/foo.log')
        self.assertTrue(conf.needs_save())
        conf.save()

        self.assertEqual(self.protocol.sets[0], ('Log', 'notice file /var/log/tor/notices.log'))
        self.assertEqual(self.protocol.sets[1], ('Log', 'info file /tmp/foo.log'))

    def test_log_set_capital(self):
        conf = TorConfig(self.protocol)

        conf.Log.append('info file /tmp/foo.log')
        self.assertTrue(conf.needs_save())
        conf.save()

        self.assertEqual(self.protocol.sets[0], ('Log', 'notice file /var/log/tor/notices.log'))
        self.assertEqual(self.protocol.sets[1], ('Log', 'info file /tmp/foo.log'))

    def test_log_set_index(self):
        conf = TorConfig(self.protocol)

        conf.log[0] = 'info file /tmp/foo.log'
        self.assertTrue(conf.needs_save())
        conf.save()

        self.assertEqual(self.protocol.sets[0], ('Log', 'info file /tmp/foo.log'))

    def test_log_set_slice(self):
        conf = TorConfig(self.protocol)

        conf.log[0:1] = ['info file /tmp/foo.log']
        self.assertTrue(conf.needs_save())
        conf.save()

        self.assertEqual(self.protocol.sets[0], ('Log', 'info file /tmp/foo.log'))
        
    def test_log_set_pop(self):
        conf = TorConfig(self.protocol)

        self.assertEqual(len(conf.log), 1)
        conf.log.pop()
        self.assertTrue(conf.needs_save())
        conf.save()

        self.assertEqual(len(conf.log), 0)
        self.assertEqual(len(self.protocol.sets), 0)
        
    def test_log_set_extend(self):
        conf = TorConfig(self.protocol)

        self.assertEqual(len(conf.log), 1)
        conf.log.extend(['info file /tmp/foo'])
        self.assertTrue(conf.needs_save())
        conf.save()

        self.assertEqual(len(conf.log), 2)
        self.assertEqual(len(self.protocol.sets), 2)
        self.assertEqual(self.protocol.sets[0], ('Log', 'notice file /var/log/tor/notices.log'))
        self.assertEqual(self.protocol.sets[1], ('Log', 'info file /tmp/foo'))
        
    def test_log_set_insert(self):
        conf = TorConfig(self.protocol)

        self.assertEqual(len(conf.log), 1)
        conf.log.insert(0, 'info file /tmp/foo')
        self.assertTrue(conf.needs_save())
        conf.save()

        self.assertEqual(len(conf.log), 2)
        self.assertEqual(len(self.protocol.sets), 2)
        self.assertEqual(self.protocol.sets[1], ('Log', 'notice file /var/log/tor/notices.log'))
        self.assertEqual(self.protocol.sets[0], ('Log', 'info file /tmp/foo'))
        
    def test_log_set_remove(self):
        conf = TorConfig(self.protocol)

        self.assertEqual(len(conf.log), 1)
        conf.log.remove('notice file /var/log/tor/notices.log')
        self.assertTrue(conf.needs_save())
        conf.save()

        self.assertEqual(len(conf.log), 0)
        self.assertEqual(len(self.protocol.sets), 0)

    def test_log_set_multiple(self):
        conf = TorConfig(self.protocol)

        self.assertEqual(len(conf.log), 1)
        conf.log[0] = 'foo'
        self.assertTrue(conf.needs_save())
        conf.log[0] = 'heavy'
        conf.log[0] = 'round'
        conf.save()

        self.assertEqual(len(self.protocol.sets), 1)
        self.assertEqual(self.protocol.sets[0], ('Log', 'round'))

    def test_set_wrong_object(self):
        conf = TorConfig(self.protocol)

        try:
            conf.log = ('this', 'is', 'a', 'tuple')
            self.fail()
        except ValueError, e:
            self.assertTrue('Not valid' in str(e))


class EventTests(unittest.TestCase):

    def test_conf_changed(self):
        control = FakeControlProtocol([])
        config = TorConfig(control)
        self.assertTrue(control.events.has_key('CONF_CHANGED'))

        control.events['CONF_CHANGED']('Foo=bar\nBar')
        self.assertEqual(len(config.config), 2)
        self.assertEqual(config.Foo, 'bar')
        self.assertEqual(config.Bar, DEFAULT_VALUE)

        


class CreateTorrcTests(unittest.TestCase):
    
    def test_create_torrc(self):
        config = TorConfig()
        config.SocksPort = 1234
        config.hiddenservices = [HiddenService(config, '/some/dir', '80 127.0.0.1:1234',
                                               'auth', 2)]
        config.Log = ['80 127.0.0.1:80', '90 127.0.0.1:90']
        config.save()
        torrc = config.create_torrc()
        self.assertEqual(torrc, '''HiddenServiceDir /some/dir
HiddenServicePort 80 127.0.0.1:1234
HiddenServiceVersion 2
HiddenServiceAuthorizeClient auth
Log 80 127.0.0.1:80
Log 90 127.0.0.1:90
SocksPort 1234
''')
        
class HiddenServiceTests(unittest.TestCase):
    def setUp(self):
        self.protocol = FakeControlProtocol([])
        self.protocol.answers.append('''config/names=
HiddenServiceOptions Virtual
HiddenServiceVersion Dependant
HiddenServiceAuthorizeClient Dependant
OK''')

    def test_options_hidden(self):
        self.protocol.answers.append('HiddenServiceDir=/fake/path\nHiddenServicePort=80 127.0.0.1:1234\n')
        
        conf = TorConfig(self.protocol)
        self.assertTrue(not conf.config.has_key('HiddenServiceOptions'))
        self.assertEqual(len(conf.HiddenServices), 1)

        self.assertTrue(not conf.needs_save())
        conf.hiddenservices.append(HiddenService(conf, '/some/dir', '80 127.0.0.1:2345', 'auth', 2))
        conf.hiddenservices[0].ports.append('443 127.0.0.1:443')
        self.assertTrue(conf.needs_save())
        conf.save()

        self.assertEqual(len(self.protocol.sets), 7)
        self.assertEqual(self.protocol.sets[0], ('HiddenServiceDir', '/fake/path'))
        self.assertEqual(self.protocol.sets[1], ('HiddenServicePort', '80 127.0.0.1:1234'))
        self.assertEqual(self.protocol.sets[2], ('HiddenServicePort', '443 127.0.0.1:443'))
        self.assertEqual(self.protocol.sets[3], ('HiddenServiceDir', '/some/dir'))
        self.assertEqual(self.protocol.sets[4], ('HiddenServicePort', '80 127.0.0.1:2345'))
        self.assertEqual(self.protocol.sets[5], ('HiddenServiceVersion', '2'))
        self.assertEqual(self.protocol.sets[6], ('HiddenServiceAuthorizeClient', 'auth'))

    def test_save_no_protocol(self):

        conf = TorConfig()
        conf.HiddenServices = [HiddenService(conf, '/fake/path', ['80 127.0.0.1:1234'])]
        conf.save()

    def test_onion_keys(self):
        self.protocol.answers.append('HiddenServiceDir=/fake/path\n')
        d = tempfile.mkdtemp()
        
        try:
            open(os.path.join(d, 'hostname'), 'w').write('public')
            open(os.path.join(d, 'private_key'), 'w').write('private')

            conf = TorConfig(self.protocol)
            hs = HiddenService(conf, d, [])

            self.assertEqual(hs.hostname, 'public')
            self.assertEqual(hs.private_key, 'private')
            
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_modify_hidden_service(self):
        self.protocol.answers.append('HiddenServiceDir=/fake/path\nHiddenServicePort=80 127.0.0.1:1234\n')
        
        conf = TorConfig(self.protocol)
        conf.hiddenservices[0].version = 3
        self.assertTrue(conf.needs_save())
        
    def test_multiple_startup_services(self):
        conf = TorConfig(FakeControlProtocol(['config/names=']))
        conf._setup_hidden_services('''HiddenServiceDir=/fake/path
HiddenServicePort=80 127.0.0.1:1234
HiddenServiceVersion=2
HiddenServiceAuthorizeClient=basic
HiddenServiceDir=/some/other/fake/path
HiddenServicePort=80 127.0.0.1:1234
HiddenServicePort=90 127.0.0.1:2345''')

        self.assertEqual(len(conf.hiddenservices), 2)

        self.assertEqual(conf.hiddenservices[0].dir, '/fake/path')
        self.assertEqual(conf.hiddenservices[0].version, 2)
        self.assertEqual(conf.hiddenservices[0].authorize_client, 'basic')
        self.assertEqual(len(conf.hiddenservices[0].ports), 1)
        self.assertEqual(conf.hiddenservices[0].ports[0], '80 127.0.0.1:1234')
        
        self.assertEqual(conf.hiddenservices[1].dir, '/some/other/fake/path')
        self.assertEqual(len(conf.hiddenservices[1].ports), 2)
        self.assertEqual(conf.hiddenservices[1].ports[0], '80 127.0.0.1:1234')
        self.assertEqual(conf.hiddenservices[1].ports[1], '90 127.0.0.1:2345')
        
    def test_hidden_service_parse_error(self):
        conf = TorConfig(FakeControlProtocol(['config/names=']))
        try:
            conf._setup_hidden_services('''FakeHiddenServiceKey=foo''')
            self.fail()
        except RuntimeError, e:
            self.assertTrue('parse' in str(e))

    def test_multiple_modify_hidden_service(self):
        self.protocol.answers.append('HiddenServiceDir=/fake/path\nHiddenServicePort=80 127.0.0.1:1234\n')
        
        conf = TorConfig(self.protocol)
        conf.hiddenservices[0].version = 3
        self.assertTrue(conf.needs_save())
        conf.hiddenservices[0].version = 4
        conf.hiddenservices[0].version = 5

        self.assertEqual(conf.hiddenservices[0].version, 5)
        conf.save()
        self.assertEqual(len(self.protocol.sets), 3)
        self.assertEqual(self.protocol.sets[0], ('HiddenServiceDir', '/fake/path'))
        self.assertEqual(self.protocol.sets[1], ('HiddenServicePort', '80 127.0.0.1:1234'))
        self.assertEqual(self.protocol.sets[2], ('HiddenServiceVersion', '5'))
        
    def test_set_save_modify(self):
        self.protocol.answers.append('')
        
        conf = TorConfig(self.protocol)

        conf.hiddenservices = [HiddenService(conf, '/fake/path', ['80 127.0.0.1:1234'], '', 3)]
        self.assertTrue(conf.needs_save())
        conf.save()

        self.assertEqual(len(conf.hiddenservices), 1)
        self.assertEqual(conf.hiddenservices[0].dir, '/fake/path')
        self.assertEqual(conf.hiddenservices[0].version, 3)
        self.assertEqual(conf.hiddenservices[0].authorize_client, '')
        conf.hiddenservices[0].ports = ['123 127.0.0.1:4321']
        conf.save()

        self.assertTrue(not conf.needs_save())
        conf.hiddenservices[0].ports.append('90 127.0.0.1:2345')
        self.assertTrue(conf.needs_save())

class FakeReactor:
    implements(IReactorCore)

    def __init__(self, test, trans, on_protocol):
        self.test = test
        self.transport = trans
        self.on_protocol = on_protocol

    def spawnProcess(self, processprotocol, bin, args, env, path, uid=None, gid=None, usePTY=None, childFDs=None):
        self.protocol = processprotocol
        self.protocol.makeConnection(self.transport)
        self.on_protocol(self.protocol)
        return self.transport
        
    def addSystemEventTrigger(self, *args):
        self.test.assertEqual(args[0], 'before')
        self.test.assertEqual(args[1], 'shutdown')
        ## we know this is just for the temporary file cleanup, so we
        ## nuke it right away to avoid polluting /tmp but calling the
        ## callback now.
        args[2]()
        
    def removeSystemEventTrigger(self, id):
        pass

class FakeProcessTransport(proto_helpers.StringTransportWithDisconnection):

    pid = -1

    def closeStdin(self):
        self.protocol.dataReceived('250 OK\r\n')
        self.protocol.dataReceived('250 OK\r\n')
        self.protocol.dataReceived('250 OK\r\n')
        self.protocol.dataReceived('650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=90 TAG=circuit_create SUMMARY="Establishing a Tor circuit"\r\n')
        self.protocol.dataReceived('650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"\r\n')
  
class LaunchTorTests(unittest.TestCase):
    def setUp(self):
        self.protocol = TorControlProtocol()
        self.protocol.connectionMade = do_nothing
        self.transport = proto_helpers.StringTransport()
        self.protocol.makeConnection(self.transport)

    def setup_complete_no_errors(self, proto):
        todel = proto.to_delete
        self.assertTrue(len(todel) > 0)
        proto.processEnded(Failure(error.ProcessDone(0)))
        self.assertEqual(len(proto.to_delete), 0)
        for f in todel:
            self.assertTrue(not os.path.exists(f))

    def setup_complete_fails(self, proto):
        todel = proto.to_delete
        self.assertTrue(len(todel) > 0)
        ## the "12" is just arbitrary, we check it later in the error-message
        proto.processEnded(Failure(error.ProcessTerminated(12, None, 'statusFIXME')))
        self.assertEqual(len(proto.to_delete), 0)
        for f in todel:
            self.assertTrue(not os.path.exists(f))

    def test_basic_launch(self):
        config = TorConfig()
        config.OrPort = 1234
        config.SocksPort = 9999

        def connector(proto, trans):
            proto._set_valid_events('STATUS_CLIENT')
            proto.makeConnection(trans)
            proto.post_bootstrap.callback(proto)
            return proto.post_bootstrap

        class OnProgress:
            def __init__(self, test, expected):
                self.test = test
                self.expected = expected

            def __call__(self, percent, tag, summary):
                self.test.assertEqual(self.expected[0], (percent, tag, summary))
                self.expected = self.expected[1:]
                self.test.assertTrue('"' not in summary)
                self.test.assertTrue(percent >= 0 and percent <= 100)            
            
        def on_protocol(proto):
            proto.outReceived('Bootstrapped 100%\n')
            proto.progress = OnProgress(self, [(90, 'circuit_create', 'Establishing a Tor circuit'),
                                               (100, 'done', 'Done')])

        trans = FakeProcessTransport()
        trans.protocol = self.protocol
        self.othertrans = trans
        creator = functools.partial(connector, self.protocol, self.transport)
        d = launch_tor(config, FakeReactor(self, trans, on_protocol), connection_creator=creator)
        d.addCallback(self.setup_complete_no_errors)
        return d
        
    def check_setup_failure(self, fail):
        self.assertTrue("with error-code 12" in fail.getErrorMessage())
        ## cancel the errback chain, we wanted this
        return None
                
    def test_launch_tor_fails(self):
        config = TorConfig()
        config.OrPort = 1234
        config.SocksPort = 9999

        def connector(proto, trans):
            proto._set_valid_events('STATUS_CLIENT')
            proto.makeConnection(trans)
            proto.post_bootstrap.callback(proto)
            return proto.post_bootstrap
            
        def on_protocol(proto):
            proto.outReceived('Bootstrapped 100%\n')
            
        trans = FakeProcessTransport()
        trans.protocol = self.protocol
        self.othertrans = trans
        creator = functools.partial(connector, self.protocol, self.transport)
        d = launch_tor(config, FakeReactor(self, trans, on_protocol), connection_creator=creator)
        d.addCallback(self.setup_complete_fails)
        d.addErrback(self.check_setup_failure)
        return d

    def setup_fails_stderr(self, fail):
        self.assertTrue('Something went horribly wrong!' in fail.getErrorMessage())
        ## cancel the errback chain, we wanted this
        return None
        
    def test_tor_produces_stderr_output(self):
        config = TorConfig()
        config.OrPort = 1234
        config.SocksPort = 9999

        def connector(proto, trans):
            proto._set_valid_events('STATUS_CLIENT')
            proto.makeConnection(trans)
            proto.post_bootstrap.callback(proto)
            return proto.post_bootstrap
            
        def on_protocol(proto):
            proto.errReceived('Something went horribly wrong!\n')
            
        trans = FakeProcessTransport()
        trans.protocol = self.protocol
        self.othertrans = trans
        creator = functools.partial(connector, self.protocol, self.transport)
        d = launch_tor(config, FakeReactor(self, trans, on_protocol), connection_creator=creator)
        d.addCallback(self.fail)        # should't get callback
        d.addErrback(self.setup_fails_stderr)
        return d
        
    def test_tor_connection_fails(self):
        """
        We fail to connect once, and then successfully connect --
        testing whether we're retrying properly on each Bootstrapped
        line from stdout.
        """
        
        config = TorConfig()
        config.OrPort = 1234
        config.SocksPort = 9999

        class Connector:
            count = 0

            def __call__(self, proto, trans):
                self.count += 1
                if self.count < 2:
                    return defer.fail(error.CannotListenError(None, None, None))

                proto._set_valid_events('STATUS_CLIENT')
                proto.makeConnection(trans)
                proto.post_bootstrap.callback(proto)
                return proto.post_bootstrap

        def on_protocol(proto):
            proto.outReceived('Bootstrapped 90%\n')
            proto.outReceived('Bootstrapped 100%\n')
            
        trans = FakeProcessTransport()
        trans.protocol = self.protocol
        self.othertrans = trans
        creator = functools.partial(Connector(), self.protocol, self.transport)
        d = launch_tor(config, FakeReactor(self, trans, on_protocol), connection_creator=creator)
        d.addCallback(self.setup_complete_fails)
        d.addErrback(self.check_setup_failure)
        return d

    def test_tor_connection_user_data_dir(self):
        """
        Test that we don't delete a user-supplied data directory.
        """

        config = TorConfig()
        config.OrPort = 1234

        class Connector:
            def __call__(self, proto, trans):
                proto._set_valid_events('STATUS_CLIENT')
                proto.makeConnection(trans)
                proto.post_bootstrap.callback(proto)
                return proto.post_bootstrap

        def on_protocol(proto):
            proto.outReceived('Bootstrapped 90%\n')
            proto.outReceived('Bootstrapped 100%\n')

        my_dir = tempfile.mkdtemp(prefix='tortmp')
        config.DataDirectory = my_dir
        trans = FakeProcessTransport()
        trans.protocol = self.protocol
        self.othertrans = trans
        creator = functools.partial(Connector(), self.protocol, self.transport)
        d = launch_tor(config, FakeReactor(self, trans, on_protocol), connection_creator=creator)
        def still_have_data_dir(proto, tester):
            proto.cleanup()             # FIXME? not really unit-testy as this is sort of internal function
            tester.assertTrue(os.path.exists(my_dir))
            delete_file_or_tree(my_dir)
        d.addCallback(still_have_data_dir, self)
        d.addErrback(self.fail)
        return d

    def test_tor_connection_user_control_port(self):
        """
        Confirm we use a user-supplied control-port properly
        """

        config = TorConfig()
        config.OrPort = 1234
        config.ControlPort = 4321

        class Connector:
            def __call__(self, proto, trans):
                proto._set_valid_events('STATUS_CLIENT')
                proto.makeConnection(trans)
                proto.post_bootstrap.callback(proto)
                return proto.post_bootstrap

        def on_protocol(proto):
            proto.outReceived('Bootstrapped 90%\n')
            proto.outReceived('Bootstrapped 100%\n')

        trans = FakeProcessTransport()
        trans.protocol = self.protocol
        self.othertrans = trans
        creator = functools.partial(Connector(), self.protocol, self.transport)
        d = launch_tor(config, FakeReactor(self, trans, on_protocol), connection_creator=creator)

        def check_control_port(proto, tester):
            ## we just want to ensure launch_tor() didn't mess with
            ## the controlport we set
            tester.assertEquals(config.ControlPort, 4321)

        d.addCallback(check_control_port, self)
        d.addErrback(self.fail)
        return d

    def test_tor_connection_default_control_port(self):
        """
        Confirm a default control-port is set if not user-supplied.
        """

        config = TorConfig()

        class Connector:
            def __call__(self, proto, trans):
                proto._set_valid_events('STATUS_CLIENT')
                proto.makeConnection(trans)
                proto.post_bootstrap.callback(proto)
                return proto.post_bootstrap

        def on_protocol(proto):
            proto.outReceived('Bootstrapped 90%\n')
            proto.outReceived('Bootstrapped 100%\n')

        trans = FakeProcessTransport()
        trans.protocol = self.protocol
        self.othertrans = trans
        creator = functools.partial(Connector(), self.protocol, self.transport)
        d = launch_tor(config, FakeReactor(self, trans, on_protocol), connection_creator=creator)

        def check_control_port(proto, tester):
            ## ensure ControlPort was set to a default value
            tester.assertEquals(config.ControlPort, 9052)

        d.addCallback(check_control_port, self)
        d.addErrback(self.fail)
        return d

    def confirm_progress(self, exp, *args, **kwargs):
        self.assertEqual(exp, args)
        self.got_progress = True
        
    def test_progress_updates(self):
        from txtorcon.torconfig import TorProcessProtocol

        self.got_progress = False;
        proto = TorProcessProtocol(None, functools.partial(self.confirm_progress,
                                                           (10, 'tag', 'summary')))
        proto.progress(10, 'tag', 'summary')
        self.assertTrue(self.got_progress)

    def test_status_updates(self):
        from txtorcon.torconfig import TorProcessProtocol

        proto = TorProcessProtocol(None)
        proto.status_client("NOTICE CONSENSUS_ARRIVED")


class FakeProtocolFactory:
    implements(IProtocolFactory)

    def buildProtocol(self, addr):
        return None
    
    def doStart(self):
        return None

    def doStop(self):
        return None

class FakeListeningPort(object):
    def startListening(self):
        print "startListening"
    def stopListening(self):
        print "stopListening"
    def getHost(self):
        return "host"
        

class FakeReactorTcp(object):
    implements(IReactorTCP)

    failures = 0

    def listenTCP(self, port, factory, **kwargs):
        if self.failures > 0:
            self.failures -= 1
            raise error.CannotListenError(None, None, None)
        
        return FakeListeningPort()
    
    def connectTCP(self, host, port, factory, **kwargs):
        print "listenTCP",port,factory,kwards
        return FakeListeningPort()
        
class EndpointTests(unittest.TestCase):

    def setUp(self):
        self.reactor = FakeReactorTcp()
        self.protocol = FakeControlProtocol([])
        self.config = TorConfig(self.protocol)

    def test_basic(self):
        ep = TCPHiddenServiceEndpoint(self.reactor, self.config, 123)
        d = ep.listen(FakeProtocolFactory())

        self.protocol.answers.append('''config/names=
HiddenServiceOptions Virtual
OK''')
        self.protocol.answers.append('HiddenServiceOptions')
        
        self.config.bootstrap()

        return d

    def test_failure(self):
        self.reactor.failures = 2
        ep = TCPHiddenServiceEndpoint(self.reactor, self.config, 123)
        d = ep.listen(FakeProtocolFactory())

        self.protocol.answers.append('''config/names=
HiddenServiceOptions Virtual
OK''')
        self.protocol.answers.append('HiddenServiceOptions')
        
        self.config.bootstrap()

        return d

    def check_error(self, failure):
        self.assertEqual(failure.type, error.CannotListenError)
        return None

    def test_too_many_failures(self):
        self.reactor.failures = 12
        ep = TCPHiddenServiceEndpoint(self.reactor, self.config, 123)
        d = ep.listen(FakeProtocolFactory())

        self.protocol.answers.append('''config/names=
HiddenServiceOptions Virtual
OK''')
        self.protocol.answers.append('HiddenServiceOptions')
        
        self.config.bootstrap()

        d.addErrback(self.check_error)

        return d
