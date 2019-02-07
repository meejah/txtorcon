from __future__ import print_function

import os
import shutil
import tempfile
import functools
import warnings
from six import StringIO
from mock import Mock, patch
from os.path import join

from zope.interface import implementer, directlyProvides
from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.internet import defer
from twisted.internet.interfaces import IReactorCore
from twisted.python.failure import Failure

from txtorcon import TorProtocolError
from txtorcon import ITorControlProtocol
from txtorcon import TorProcessProtocol
from txtorcon import TorConfig
from txtorcon import DEFAULT_VALUE
from txtorcon import HiddenService
from txtorcon import launch
from txtorcon import TorNotFound

from txtorcon.torconfig import CommaList
from txtorcon.torconfig import launch_tor
from txtorcon.torconfig import EphemeralHiddenService
from txtorcon.onion import _parse_client_keys
from txtorcon.onion import FilesystemOnionService
from txtorcon.onion import EphemeralOnionService
from txtorcon.onion import FilesystemAuthenticatedOnionService
from txtorcon.onion import AuthBasic

from txtorcon.testutil import FakeControlProtocol


class CheckAnswer:

    def __init__(self, test, ans):
        self.answer = ans
        self.test = test

    def __call__(self, x):
        self.test.assertEqual(x, self.answer)


class DefaultsTests(unittest.TestCase):

    @defer.inlineCallbacks
    def test_default_port(self):
        protocol = FakeControlProtocol([])
        protocol.answers.append('config/names=\nfoo Boolean')
        protocol.answers.append('config/defaults=\nfoo 1')
        protocol.answers.append({'foo': ''})
        config = TorConfig(protocol)
        yield config.post_bootstrap

        self.assertEqual(config.foo, True)

    @defer.inlineCallbacks
    def test_default_linelist(self):
        protocol = FakeControlProtocol([])
        protocol.answers.append('config/names=\nSomeThing LineList')
        protocol.answers.append('config/defaults=\nSomeThing value0\nSomeThing value1')
        protocol.answers.append({'SomeThing': 'DEFAULT'})
        config = TorConfig(protocol)
        yield config.post_bootstrap

        self.assertEqual(list(config.SomeThing), ['value0', 'value1'])


class PortLineDefaultsTests(unittest.TestCase):

    @defer.inlineCallbacks
    def test_default_port(self):
        protocol = FakeControlProtocol([])
        protocol.answers.append('config/names=\nSocksPortLines Dependant')
        protocol.answers.append('config/defaults=\nSocksPort 1234\nSocksPort 4321')
        protocol.answers.append({'SocksPort': 'auto'})
        config = TorConfig(protocol)
        yield config.post_bootstrap

        self.assertTrue('1234' in config.SocksPort)
        self.assertTrue('4321' in config.SocksPort)

    @defer.inlineCallbacks
    def test_default_port_but_not_default(self):
        protocol = FakeControlProtocol([])
        protocol.answers.append('config/names=\nSocksPortLines Dependant')
        protocol.answers.append('config/defaults=\nSocksPort 1234\nSocksPort 4321')
        protocol.answers.append({'SocksPort': '8888'})
        config = TorConfig(protocol)
        yield config.post_bootstrap

        self.assertTrue('8888' in config.SocksPort)
        self.assertFalse('4321' in config.SocksPort)
        self.assertFalse('1234' in config.SocksPort)

    @defer.inlineCallbacks
    def test_many_defaults(self):
        protocol = FakeControlProtocol([])
        protocol.answers.append('config/names=\nSocksPortLines Dependant')
        protocol.answers.append('config/defaults=\nSocksPort 1234\nSocksPort 4321\nSocksPort 42')
        protocol.answers.append({'SocksPort': 'auto'})
        config = TorConfig(protocol)
        yield config.post_bootstrap

        self.assertTrue('1234' in config.SocksPort)
        self.assertTrue('4321' in config.SocksPort)
        self.assertTrue('42' in config.SocksPort)
        self.assertEqual(3, len(config.SocksPort))

    @defer.inlineCallbacks
    def test_no_default(self):
        protocol = FakeControlProtocol([])
        protocol.answers.append('config/names=\nSocksPortLines Dependant')
        protocol.answers.append('config/defaults=')
        protocol.answers.append({'SocksPort': 'auto'})
        protocol.answers.append('')
        config = TorConfig(protocol)
        yield config.post_bootstrap

        self.assertEqual(0, len(config.SocksPort))

    @defer.inlineCallbacks
    def test_default_portlines(self):
        protocol = FakeControlProtocol([])
        protocol.answers.append('config/names=\nSocksPortLines Dependant')
        protocol.answers.append('config/defaults=')
        protocol.answers.append({'SocksPort': 'auto'})
        protocol.answers.append('9123')
        protocol.answers.append({'onions/current': ''})
        config = TorConfig(protocol)
        yield config.post_bootstrap

        self.assertEqual(
            ['9123'],
            list(config.SocksPort),
        )

    @defer.inlineCallbacks
    def test_onions_current(self):
        protocol = FakeControlProtocol([])
        protocol.answers.append('config/names=\nSocksPortLines Dependant')
        protocol.answers.append('config/defaults=')
        protocol.answers.append({'SocksPort': 'auto'})
        protocol.answers.append('9123')
        # hmmmm? why aren't these the other way around?
        protocol.answers.append({'onions/detached': 'asdfasdf.onion'})
        protocol.answers.append({'onions/current': 'something.onion'})
        config = TorConfig(protocol)
        yield config.post_bootstrap

        self.assertEqual(
            ['9123'],
            list(config.SocksPort),
        )
        self.assertEqual(1, len(config.EphemeralOnionServices))
        self.assertEqual(1, len(config.DetachedOnionServices))

    @defer.inlineCallbacks
    def test_no_defaults_support(self):
        protocol = FakeControlProtocol([])
        protocol.answers.append('config/names=\nSocksPortLines Dependant')
        protocol.answers.append(Failure(TorProtocolError(552, "foo")))
        protocol.answers.append({'SocksPort': 'auto'})
        protocol.answers.append('')
        config = TorConfig(protocol)
        yield config.post_bootstrap

        self.assertEqual(0, len(config.SocksPort))


class ConfigTests(unittest.TestCase):

    def setUp(self):
        self.protocol = FakeControlProtocol([])

    def test_boolean_parse_error(self):
        self.protocol.answers.append('config/names=\nfoo Boolean')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'foo': 'bar'})
        cfg = TorConfig(self.protocol)
        return self.assertFailure(cfg.post_bootstrap, ValueError)

    def test_create(self):

        @implementer(ITorControlProtocol)
        class FakeProtocol(object):
            post_bootstrap = defer.succeed(None)

            def add_event_listener(*args, **kw):
                return defer.succeed(None)

            def get_info_raw(*args, **kw):
                return defer.succeed('config/names=')
        TorConfig.from_protocol(FakeProtocol())

    def test_contains(self):
        cfg = TorConfig()
        cfg.ControlPort = 4455
        self.assertTrue('ControlPort' in cfg)

    def test_boolean_parser(self):
        self.protocol.answers.append('config/names=\nfoo Boolean\nbar Boolean')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'foo': '0'})
        self.protocol.answers.append({'bar': '1'})
        # FIXME does a Tor controller only ever send "0" and "1" for
        # true/false? Or do we need to accept others?

        conf = TorConfig(self.protocol)
        self.assertTrue(conf.foo is False)
        self.assertTrue(conf.bar is True)

    def test_save_boolean(self):
        self.protocol.answers.append('config/names=\nfoo Boolean\nbar Boolean')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'foo': '0'})
        self.protocol.answers.append({'bar': '1'})

        conf = TorConfig(self.protocol)

        # save some boolean value
        conf.foo = True
        conf.bar = False
        conf.save()
        self.assertEqual(set(self.protocol.sets),
                         set([('foo', 1), ('bar', 0)]))

    def test_read_boolean_after_save(self):
        self.protocol.answers.append('config/names=\nfoo Boolean\nbar Boolean')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'foo': '0'})
        self.protocol.answers.append({'bar': '1'})

        conf = TorConfig(self.protocol)

        # save some boolean value
        conf.foo = True
        conf.bar = False
        conf.save()
        self.assertTrue(conf.foo is True, msg="foo not True: %s" % conf.foo)
        self.assertTrue(conf.bar is False, msg="bar not False: %s" % conf.bar)

    def test_save_boolean_with_strange_values(self):
        self.protocol.answers.append('config/names=\nfoo Boolean\nbar Boolean')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'foo': '0'})
        self.protocol.answers.append({'bar': '1'})

        conf = TorConfig(self.protocol)
        # save some non-boolean value
        conf.foo = "Something True"
        conf.bar = 0
        conf.save()
        self.assertEqual(set(self.protocol.sets),
                         set([('foo', 1), ('bar', 0)]))

    def test_boolean_auto_parser(self):
        self.protocol.answers.append(
            'config/names=\nfoo Boolean+Auto\nbar Boolean+Auto\nbaz Boolean+Auto'
        )
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'foo': '0'})
        self.protocol.answers.append({'bar': '1'})
        self.protocol.answers.append({'baz': 'auto'})

        conf = TorConfig(self.protocol)
        self.assertEqual(conf.foo, 0)
        self.assertEqual(conf.bar, 1)
        self.assertEqual(conf.baz, -1)

    def test_save_boolean_auto(self):
        self.protocol.answers.append(
            'config/names=\nfoo Boolean+Auto\nbar Boolean+Auto\nbaz Boolean+Auto\nqux Boolean+Auto'
        )
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'foo': '1'})
        self.protocol.answers.append({'bar': '1'})
        self.protocol.answers.append({'baz': '1'})
        self.protocol.answers.append({'qux': '1'})

        conf = TorConfig(self.protocol)
        conf.foo = 1
        conf.bar = 0
        conf.baz = True
        conf.qux = -1
        conf.save()
        self.assertEqual(set(self.protocol.sets),
                         set([('foo', 1),
                              ('bar', 0),
                              ('baz', 1),
                              ('qux', 'auto')]))
        self.assertEqual(conf.foo, 1)
        self.assertEqual(conf.bar, 0)
        self.assertEqual(conf.baz, 1)
        self.assertEqual(conf.qux, -1)

    def test_save_invalid_boolean_auto(self):
        self.protocol.answers.append(
            'config/names=\nfoo Boolean+Auto'
        )
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'foo': '1'})

        conf = TorConfig(self.protocol)
        for value in ('auto', 'True', 'False', None):
            try:
                conf.foo = value
            except (ValueError, TypeError):
                pass
            else:
                self.fail("Invalid value '%s' allowed" % value)
            conf.save()
            self.assertEqual(self.protocol.sets, [])

    def test_string_parser(self):
        self.protocol.answers.append('config/names=\nfoo String')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'foo': 'bar'})
        conf = TorConfig(self.protocol)
        self.assertEqual(conf.foo, 'bar')

    def test_int_parser(self):
        self.protocol.answers.append('config/names=\nfoo Integer')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'foo': '123'})
        conf = TorConfig(self.protocol)
        self.assertEqual(conf.foo, 123)

    def test_int_validator(self):
        self.protocol.answers.append('config/names=\nfoo Integer')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'foo': '123'})
        conf = TorConfig(self.protocol)

        conf.foo = 2.33
        conf.save()
        self.assertEqual(conf.foo, 2)

        conf.foo = '1'
        conf.save()
        self.assertEqual(conf.foo, 1)

        conf.foo = '-100'
        conf.save()
        self.assertEqual(conf.foo, -100)

        conf.foo = 0
        conf.save()
        self.assertEqual(conf.foo, 0)

        conf.foo = '0'
        conf.save()
        self.assertEqual(conf.foo, 0)

        for value in ('no', 'Not a value', None):
            try:
                conf.foo = value
            except (ValueError, TypeError):
                pass
            else:
                self.fail("No excpetion thrown")

    def test_int_parser_error(self):
        self.protocol.answers.append('config/names=\nfoo Integer')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'foo': '123foo'})
        cfg = TorConfig(self.protocol)
        self.assertFailure(cfg.post_bootstrap, ValueError)

    def test_int_parser_error_2(self):
        self.protocol.answers.append('config/names=\nfoo Integer')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'foo': '1.23'})
        cfg = TorConfig(self.protocol)
        return self.assertFailure(cfg.post_bootstrap, ValueError)

    def test_linelist_parser(self):
        self.protocol.answers.append('config/names=\nfoo LineList')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'foo': 'bar\nbaz'})
        conf = TorConfig(self.protocol)
        self.assertEqual(conf.foo, ['bar', 'baz'])

    def test_listlist_parser_with_list(self):
        self.protocol.answers.append('config/names=\nfoo LineList')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'foo': [1, 2, 3]})

        conf = TorConfig(self.protocol)
        self.assertEqual(conf.foo, ['1', '2', '3'])

    def test_float_parser(self):
        self.protocol.answers.append('config/names=\nfoo Float')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'foo': '1.23'})
        conf = TorConfig(self.protocol)
        self.assertEqual(conf.foo, 1.23)

    def test_float_parser_error(self):
        self.protocol.answers.append('config/names=\nfoo Float')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'foo': '1.23fff'})
        cfg = TorConfig(self.protocol)
        return self.assertFailure(cfg.post_bootstrap, ValueError)

    def test_list(self):
        self.protocol.answers.append('config/names=\nbing CommaList')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'bing': 'foo,bar,baz'})
        conf = TorConfig(self.protocol)
        self.assertEqual(conf.config['bing'], ['foo', 'bar', 'baz'])
        # self.assertEqual(conf.bing, ['foo','bar','baz'])

    def test_single_list(self):
        self.protocol.answers.append('config/names=\nbing CommaList')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'bing': 'foo'})
        conf = TorConfig(self.protocol)
        self.assertTrue(conf.post_bootstrap.called)
        self.assertEqual(conf.config['bing'], ['foo'])

    def test_multi_list_space(self):
        self.protocol.answers.append('config/names=\nbing CommaList')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'bing': 'foo, bar , baz'})
        conf = TorConfig(self.protocol)
        self.assertEqual(conf.bing, ['foo', 'bar', 'baz'])

    def test_descriptor_access(self):
        self.protocol.answers.append('config/names=\nbing CommaList')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'bing': 'foo,bar'})

        conf = TorConfig(self.protocol)
        self.assertEqual(conf.config['bing'], ['foo', 'bar'])
        self.assertEqual(conf.bing, ['foo', 'bar'])

        self.protocol.answers.append('250 OK')
        conf.bing = ['a', 'b']
        self.assertEqual(conf.bing, ['foo', 'bar'])

        d = conf.save()

        def confirm(conf):
            self.assertEqual(conf.config['bing'], ['a', 'b'])
            self.assertEqual(conf.bing, ['a', 'b'])

        d.addCallbacks(confirm, self.fail)
        return d

    def test_unknown_descriptor(self):
        self.protocol.answers.append('config/names=\nbing CommaList')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'bing': 'foo'})

        conf = TorConfig(self.protocol)
        try:
            conf.foo
            self.assertTrue(False)
        except KeyError as e:
            self.assertTrue('foo' in str(e))

    def test_invalid_parser(self):
        self.protocol.answers.append(
            'config/names=\nSomethingExciting NonExistantParserType'
        )
        self.protocol.answers.append('')  # defaults
        cfg = TorConfig(self.protocol)
        return self.assertFailure(cfg.post_bootstrap, RuntimeError)

    def test_iteration(self):
        conf = TorConfig()
        conf.SOCKSPort = 9876
        conf.save()
        x = list(conf)
        self.assertEqual(x, ['SOCKSPort'])
        conf.save()

    def test_get_type(self):
        self.protocol.answers.append(
            'config/names=\nSomethingExciting CommaList\nHiddenServices Dependant'
        )
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'SomethingExciting': 'a,b'})
        conf = TorConfig(self.protocol)

        self.assertEqual(conf.get_type('SomethingExciting'), CommaList)
        self.assertEqual(conf.get_type('HiddenServices'), FilesystemOnionService)

    def test_immediate_hiddenservice_append(self):
        '''issue #88. we check that a .append(hs) works on a blank TorConfig'''
        conf = TorConfig()
        hs = HiddenService(conf, '/dev/null', ['80 127.0.0.1:1234'])
        conf.HiddenServices.append(hs)
        self.assertEqual(len(conf.HiddenServices), 1)
        self.assertEqual(conf.HiddenServices[0], hs)

    def foo(self, *args):
        print("FOOO", args)

    def test_accept_all_postbootstrap(self):
        # test that doPostbootstrap still works in "accept_all" mode
        self.protocol.answers.append('config/names=\nORPort Port')
        self.protocol.answers.append('')  # defaults
        # we can't answer right away, or we do all the _do_setup
        # callbacks before _setup_ is set -- but we need to do an
        # answer callback after that to trigger this bug

        conf = TorConfig(self.protocol)
        self.assertTrue('_setup_' in conf.__dict__)
        self.protocol.answer_pending({'ORPort': 1})

    def test_immediate_bootstrap(self):
        self.protocol.post_bootstrap = None
        self.protocol.answers.append('config/names=\nfoo Boolean')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'foo': '0'})
        conf = TorConfig(self.protocol)
        self.assertTrue('foo' in conf.config)

    def test_multiple_orports(self):
        self.protocol.post_bootstrap = None
        self.protocol.answers.append('config/names=\nOrPort CommaList')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'OrPort': '1234'})
        conf = TorConfig(self.protocol)
        conf.OrPort = ['1234', '4321']
        conf.save()
        self.assertEqual(self.protocol.sets, [('OrPort', '1234'),
                                              ('OrPort', '4321')])

    def test_set_multiple(self):
        self.protocol.answers.append('config/names=\nAwesomeKey String')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'AwesomeKey': 'foo'})

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
        self.protocol.answers.append(
            'config/names=\nLog LineList\nFoo String'''
        )
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append(
            {'Log': 'notice file /var/log/tor/notices.log'}
        )
        self.protocol.answers.append({'Foo': 'foo'})
        conf = TorConfig(self.protocol)

        conf.log.append('info file /tmp/foo.log')
        conf.foo = 'bar'
        self.assertTrue(conf.needs_save())
        conf.save()
        conf.save()  # just for the code coverage...

        self.assertTrue(not conf.needs_save())
        self.protocol.sets = []
        conf.save()
        self.assertEqual(self.protocol.sets, [])

    def test_set_save_modify(self):
        self.protocol.answers.append('config/names=\nLog LineList')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append(
            {'Log': 'notice file /var/log/tor/notices.log'}
        )
        conf = TorConfig(self.protocol)

        conf.log = []
        self.assertTrue(conf.needs_save())
        conf.save()

        conf.log.append('notice file /tmp/foo.log')
        self.assertTrue(conf.needs_save())

    def test_proper_sets(self):
        self.protocol.answers.append('config/names=\nLog LineList')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'Log': 'foo'})

        conf = TorConfig(self.protocol)
        conf.log.append('bar')
        conf.save()

        self.assertEqual(len(self.protocol.sets), 2)
        self.assertEqual(self.protocol.sets[0], ('Log', 'foo'))
        self.assertEqual(self.protocol.sets[1], ('Log', 'bar'))

    @defer.inlineCallbacks
    def test_attach_protocol(self):
        self.protocol.answers.append('config/names=\nLog LineList')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append({'Log': 'foo'})

        conf = TorConfig()
        d = conf.attach_protocol(self.protocol)
        yield d

        conf.log.append('bar')
        yield conf.save()

        self.assertEqual(len(self.protocol.sets), 2)
        self.assertEqual(self.protocol.sets[0], ('Log', 'foo'))
        self.assertEqual(self.protocol.sets[1], ('Log', 'bar'))

    def test_attach_protocol_but_already_have_one(self):
        conf = TorConfig(self.protocol)
        self.assertRaises(RuntimeError, conf.attach_protocol, self.protocol)

    def test_no_confchanged_event(self):
        conf = TorConfig(self.protocol)
        self.protocol.add_event_listener = Mock(side_effect=RuntimeError)
        d = defer.Deferred()
        self.protocol.get_info_raw = Mock(return_value=d)
        conf.bootstrap()
        # this should log a message, do we really care what?

    def test_attribute_access(self):
        conf = TorConfig(self.protocol)
        self.assertNotIn('_accept_all_', conf.__dict__)
        self.assertNotIn('foo', conf)


class LogTests(unittest.TestCase):

    def setUp(self):
        self.protocol = FakeControlProtocol([])
        self.protocol.answers.append('config/names=\nLog LineList''')
        self.protocol.answers.append('')  # defaults
        self.protocol.answers.append(
            {'Log': 'notice file /var/log/tor/notices.log'}
        )

    def test_log_set(self):
        conf = TorConfig(self.protocol)

        conf.log.append('info file /tmp/foo.log')
        self.assertTrue(conf.needs_save())
        conf.save()

        self.assertEqual(
            self.protocol.sets[0],
            ('Log', 'notice file /var/log/tor/notices.log')
        )
        self.assertEqual(
            self.protocol.sets[1],
            ('Log', 'info file /tmp/foo.log')
        )

    def test_log_set_capital(self):
        conf = TorConfig(self.protocol)

        conf.Log.append('info file /tmp/foo.log')
        self.assertTrue(conf.needs_save())
        conf.save()

        self.assertEqual(
            self.protocol.sets[0],
            ('Log', 'notice file /var/log/tor/notices.log')
        )
        self.assertEqual(
            self.protocol.sets[1],
            ('Log', 'info file /tmp/foo.log')
        )

    def test_log_set_index(self):
        conf = TorConfig(self.protocol)

        conf.log[0] = 'info file /tmp/foo.log'
        self.assertTrue(conf.needs_save())
        conf.save()

        self.assertEqual(
            self.protocol.sets[0],
            ('Log', 'info file /tmp/foo.log')
        )

    def test_log_set_slice(self):
        conf = TorConfig(self.protocol)

        conf.log[0:1] = ['info file /tmp/foo.log']
        self.assertTrue(conf.needs_save())
        conf.save()

        self.assertEqual(1, len(self.protocol.sets))
        self.assertEqual(
            self.protocol.sets[0],
            ('Log', 'info file /tmp/foo.log')
        )

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
        self.assertEqual(
            self.protocol.sets[0],
            ('Log', 'notice file /var/log/tor/notices.log')
        )
        self.assertEqual(
            self.protocol.sets[1],
            ('Log', 'info file /tmp/foo')
        )

    def test_log_set_insert(self):
        conf = TorConfig(self.protocol)

        self.assertEqual(len(conf.log), 1)
        conf.log.insert(0, 'info file /tmp/foo')
        self.assertTrue(conf.needs_save())
        conf.save()

        self.assertEqual(len(conf.log), 2)
        self.assertEqual(len(self.protocol.sets), 2)
        self.assertEqual(
            self.protocol.sets[1],
            ('Log', 'notice file /var/log/tor/notices.log')
        )
        self.assertEqual(
            self.protocol.sets[0],
            ('Log', 'info file /tmp/foo')
        )

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
        self.assertTrue(conf.post_bootstrap.called)
        try:
            conf.log = ('this', 'is', 'a', 'tuple')
            self.fail()
        except ValueError as e:
            self.assertTrue('Not valid' in str(e))


class EventTests(unittest.TestCase):

    def test_conf_changed(self):
        control = FakeControlProtocol([])
        config = TorConfig(control)
        self.assertTrue('CONF_CHANGED' in control.events)

        control.events['CONF_CHANGED']('Foo=bar\nBar')
        self.assertEqual(len(config.config), 2)
        self.assertEqual(config.Foo, 'bar')
        self.assertEqual(config.Bar, DEFAULT_VALUE)

    def test_conf_changed_parsed(self):
        '''
        Create a configuration which holds boolean types. These types
        have to be parsed as booleans.
        '''
        protocol = FakeControlProtocol([])
        protocol.answers.append('config/names=\nFoo Boolean\nBar Boolean')
        protocol.answers.append('')  # defaults
        protocol.answers.append({'Foo': '0'})
        protocol.answers.append({'Bar': '1'})

        config = TorConfig(protocol)
        # Initial value is not tested here
        protocol.events['CONF_CHANGED']('Foo=1\nBar=0')

        msg = "Foo is not True: %r" % config.Foo
        self.assertTrue(config.Foo is True, msg=msg)

        msg = "Foo is not False: %r" % config.Bar
        self.assertTrue(config.Bar is False, msg=msg)

    def test_conf_changed_invalid_values(self):
        protocol = FakeControlProtocol([])
        protocol.answers.append('config/names=\nFoo Integer\nBar Integer')
        protocol.answers.append('')  # defaults
        protocol.answers.append({'Foo': '0'})
        protocol.answers.append({'Bar': '1'})

        # Doing It For The Side Effects. Hoo boy.
        TorConfig(protocol)
        # Initial value is not tested here
        try:
            protocol.events['CONF_CHANGED']('Foo=INVALID\nBar=VALUES')
        except (ValueError, TypeError):
            pass
        else:
            self.fail("No excpetion thrown")


class CreateTorrcTests(unittest.TestCase):

    def test_create_torrc(self):
        config = TorConfig()
        config.SocksPort = 1234
        config.hiddenservices = [
            HiddenService(config, '/some/dir', '80 127.0.0.1:1234',
                          'auth', 2, True)
        ]
        config.Log = ['80 127.0.0.1:80', '90 127.0.0.1:90']
        config.save()
        torrc = config.create_torrc()
        lines = torrc.split('\n')
        lines.sort()
        torrc = '\n'.join(lines).strip()
        self.assertEqual(torrc, '''HiddenServiceAuthorizeClient auth
HiddenServiceDir /some/dir
HiddenServicePort 80 127.0.0.1:1234
HiddenServiceVersion 2
Log 80 127.0.0.1:80
Log 90 127.0.0.1:90
SocksPort 1234''')


class SocksEndpointTests(unittest.TestCase):

    def setUp(self):
        self.reactor = Mock()
        self.config = TorConfig()
        self.config.SocksPort = []

    def test_nothing_configurd(self):
        with self.assertRaises(Exception) as ctx:
            self.config.socks_endpoint(self.reactor, '1234')
        self.assertTrue('No SOCKS ports configured' in str(ctx.exception))

    def test_default(self):
        self.config.SocksPort = ['1234', '4321']
        ep = self.config.socks_endpoint(self.reactor)

        factory = Mock()
        ep.connect(factory)
        self.assertEqual(1, len(self.reactor.mock_calls))
        call = self.reactor.mock_calls[0]
        self.assertEqual('connectTCP', call[0])
        self.assertEqual('127.0.0.1', call[1][0])
        self.assertEqual(1234, call[1][1])

    def test_explicit_host(self):
        self.config.SocksPort = ['127.0.0.20:1234']
        ep = self.config.socks_endpoint(self.reactor)

        factory = Mock()
        ep.connect(factory)
        self.assertEqual(1, len(self.reactor.mock_calls))
        call = self.reactor.mock_calls[0]
        self.assertEqual('connectTCP', call[0])
        self.assertEqual('127.0.0.20', call[1][0])
        self.assertEqual(1234, call[1][1])

    def test_something_not_configured(self):
        self.config.SocksPort = ['1234', '4321']
        with self.assertRaises(Exception) as ctx:
            self.config.socks_endpoint(self.reactor, '1111')
        self.assertTrue('No SOCKSPort configured' in str(ctx.exception))

    def test_unix_socks(self):
        self.config.SocksPort = ['unix:/foo']
        self.config.socks_endpoint(self.reactor, 'unix:/foo')

    def test_with_options(self):
        self.config.SocksPort = ['9150 IPv6Traffic PreferIPv6 KeepAliveIsolateSOCKSAuth']
        ep = self.config.socks_endpoint(self.reactor, 9150)

        factory = Mock()
        ep.connect(factory)
        self.assertEqual(1, len(self.reactor.mock_calls))
        call = self.reactor.mock_calls[0]
        self.assertEqual('connectTCP', call[0])
        self.assertEqual('127.0.0.1', call[1][0])
        self.assertEqual(9150, call[1][1])

    def test_with_options_in_ask(self):
        self.config.SocksPort = ['9150 IPv6Traffic PreferIPv6 KeepAliveIsolateSOCKSAuth']

        with self.assertRaises(Exception) as ctx:
            self.config.socks_endpoint(self.reactor,
                                       '9150 KeepAliveIsolateSOCKSAuth')
        self.assertTrue("Can't specify options" in str(ctx.exception))


class CreateSocksEndpointTests(unittest.TestCase):

    def setUp(self):
        self.reactor = Mock()
        self.config = TorConfig()
        self.config.SocksPort = []
        self.config.bootstrap = defer.succeed(self.config)

    @defer.inlineCallbacks
    def test_create_default_no_ports(self):
        with self.assertRaises(Exception) as ctx:
            yield self.config.create_socks_endpoint(self.reactor, None)
        self.assertTrue('no SocksPorts configured' in str(ctx.exception))

    @defer.inlineCallbacks
    def test_create_default(self):
        self.config.SocksPort = ['9150']
        ep = yield self.config.create_socks_endpoint(self.reactor, None)

        factory = Mock()
        ep.connect(factory)
        self.assertEqual(1, len(self.reactor.mock_calls))
        call = self.reactor.mock_calls[0]
        self.assertEqual('connectTCP', call[0])
        self.assertEqual('127.0.0.1', call[1][0])
        self.assertEqual(9150, call[1][1])

    @defer.inlineCallbacks
    def test_create_tcp(self):
        ep = yield self.config.create_socks_endpoint(
            self.reactor, "9050",
        )

        factory = Mock()
        ep.connect(factory)
        self.assertEqual(1, len(self.reactor.mock_calls))
        call = self.reactor.mock_calls[0]
        self.assertEqual('connectTCP', call[0])
        self.assertEqual('127.0.0.1', call[1][0])
        self.assertEqual(9050, call[1][1])

    @defer.inlineCallbacks
    def test_create_error_on_save(self):
        self.config.SocksPort = []

        def boom(*args, **kw):
            raise TorProtocolError(551, "Something bad happened")

        with patch.object(TorConfig, 'save', boom):
            with self.assertRaises(Exception) as ctx:
                yield self.config.create_socks_endpoint(self.reactor, 'unix:/foo')
        err = str(ctx.exception)
        self.assertTrue('error from Tor' in err)
        self.assertTrue('specific ownership/permissions requirements' in err)


class HiddenServiceTests(unittest.TestCase):

    def setUp(self):
        self.protocol = FakeControlProtocol([])
        self.protocol.answers.append('''config/names=
HiddenServiceOptions Virtual
HiddenServiceVersion Dependant
HiddenServiceDirGroupReadable Dependant
HiddenServiceAuthorizeClient Dependant''')
        self.protocol.answers.append('')  # defaults

    @defer.inlineCallbacks
    def test_config_client_keys(self):
        self.protocol.answers.append('')  # no hiddenservices by default
        conf = TorConfig(self.protocol)
        yield conf.post_bootstrap
        self.assertTrue(conf.post_bootstrap.called)
        fakedir = self.mktemp()
        os.mkdir(fakedir)
        with open(join(fakedir, 'hostname'), 'w') as f:
            for name in ['alice', 'bob']:
                f.write('hostname_{name} cookie_{name} # client: {name}\n'.format(name=name))
        with open(join(fakedir, 'client_keys'), 'w') as f:
            for name in ['alice', 'bob']:
                f.write('''client-name {name}
descriptor-cookie CVAQuIn8iSsYo4KXW2Ljvw==
client-key
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDgE+4otmhhRInd2IyZemfPGYjFiYEGCCnaVWQ7JpZv25atvxuj
RB+S1PnSST6V2brF83vwaRuR4QWtFHz8v8VmUPDXcVEGoGQ+oQUrnwgGLTseBYJE
n9uY8snE7755mrsddbMorLjg2JhmoTFmGUqga1YsypqZ39H5K0qsfRw2kwIDAQAB
AoGAFoSqOFksYCn9GNg8OOg+KmfMgN1yo+KKIjDWo8Ma9x7AI7HC20NrUNwqRuGp
cnGw/VecqupFJQHSCjS24sd61L9D0OZ7NHOWsBhpUlQ5tlM3xxCz7PQmSsISro/h
IFAsAzCdhA7ies6our9m0vO93WsZTPE32hEmHCS476SvyBECQQD0OitF1gRhJ550
rAkLnZwIQlVzNH1iK10AesgivBbAw2ywkeolplUp5l0cPrckrtCZW7FDZi6wgHhw
hq2q/jetAkEA6uEczfRTYJ762pZxk/VQ17GP4T/0LBITCm4PIDQ13etuqoPe+AI7
aOcAayecbmWA9CgJdmHE77g5zDcddxrvPwJBAKG2vp6AZuf59uckXtztILsrSS9+
ayOMuQkvQ8QULTC4dgi4pYUGjU+wNKkWMei9RGy3lTmeuH2wo49G7knSCQUCQQC+
1iiRLfKQjptC/vlJPghxN9OvMEczh3vw/XtMrx8VMDS6VmrTFv0uPoIYjhaLm+0q
c1080jMwkn5jbmSCYWABAkB28YVDOpAbxRqb/7u4kYFoohWb4YpY9uBkqA9FMwsg
DnkEGTrOUFZ7CbDp+SM18BjmFXI2n0bFJEznXFhH+Awz
-----END RSA PRIVATE KEY-----
'''.format(name=name))

        hs = FilesystemAuthenticatedOnionService(
            conf, fakedir, ['1 127.0.0.1:12345'],
            auth=AuthBasic(['alice']),
        )
        hs._private_key('alice')

    @defer.inlineCallbacks
    def test_config_client_auth_service(self):
        self.protocol.answers.append('')  # no hiddenservices by default
        conf = TorConfig(self.protocol)
        yield conf.post_bootstrap
        self.assertTrue(conf.post_bootstrap.called)
        fakedir = self.mktemp()
        os.mkdir(fakedir)
        with open(join(fakedir, 'hostname'), 'w') as f:
            for name in ['alice', 'bob']:
                f.write('hostname_{name} cookie_{name} # client: {name}\n'.format(name=name))

        # create a client-auth'd onion service, but only "add" one of
        # its newly created clients
        hs = FilesystemAuthenticatedOnionService(
            conf, fakedir, ['1 127.0.0.1:12345'],
            auth=AuthBasic(['alice', 'bob']),
            group_readable=True,
        )
        hs.add_client(
            name="carol",
            hostname="hostname_carol",
            ports=['1 127.0.0.1:12345'],
            token="cookie_carol",
        )
        yield conf.save()

    @defer.inlineCallbacks
    def test_options_hidden(self):
        self.protocol.answers.append(
            'HiddenServiceDir=/fake/path\nHiddenServicePort=80 '
            '127.0.0.1:1234\nHiddenServiceDirGroupReadable=1\n'
        )

        conf = TorConfig(self.protocol)
        yield conf.post_bootstrap
        self.assertTrue(conf.post_bootstrap.called)
        self.assertTrue('HiddenServiceOptions' not in conf.config)
        self.assertTrue('HiddenServices' in conf.config)
        self.assertEqual(len(conf.HiddenServices), 1)

        self.assertTrue(not conf.needs_save())
        conf.hiddenservices.append(
            HiddenService(conf, '/some/dir', '80 127.0.0.1:2345', 'auth', 2, True)
        )
        conf.hiddenservices[0].ports.append('443 127.0.0.1:443')
        self.assertTrue(conf.needs_save())
        conf.save()

        self.assertEqual(len(self.protocol.sets), 9)
        self.assertEqual(self.protocol.sets[0], ('HiddenServiceDir', '/fake/path'))
        self.assertEqual(self.protocol.sets[1], ('HiddenServiceDirGroupReadable', '1'))
        self.assertEqual(self.protocol.sets[2], ('HiddenServicePort', '80 127.0.0.1:1234'))
        self.assertEqual(self.protocol.sets[3], ('HiddenServicePort', '443 127.0.0.1:443'))
        self.assertEqual(self.protocol.sets[4], ('HiddenServiceDir', '/some/dir'))
        self.assertEqual(self.protocol.sets[5], ('HiddenServiceDirGroupReadable', '1'))
        self.assertEqual(self.protocol.sets[6], ('HiddenServicePort', '80 127.0.0.1:2345'))
        self.assertEqual(self.protocol.sets[7], ('HiddenServiceVersion', '2'))
        self.assertEqual(self.protocol.sets[8], ('HiddenServiceAuthorizeClient', 'auth'))

    def test_save_no_protocol(self):
        conf = TorConfig()
        conf.HiddenServices = [HiddenService(conf, '/fake/path', ['80 127.0.0.1:1234'])]
        conf.save()

    def test_two_hidden_services_before_save(self):
        conf = TorConfig()
        conf.HiddenServices = [HiddenService(conf, '/fake/path', ['80 127.0.0.1:1234'])]
        conf.HiddenServices.append(HiddenService(conf, '/fake/path/two', ['1234 127.0.0.1:1234']))
        conf.save()
        self.assertEqual(2, len(conf.HiddenServices))

    def test_hs_ephemeral_wrong_list(self):
        conf = TorConfig()
        conf.HiddenServices.append(EphemeralOnionService(conf, []))
        with self.assertRaises(ValueError) as ctx:
            conf.save()
        self.assertIn(
            "ephemeral services must be created with",
            str(ctx.exception)
        )

    def test_onion_keys(self):
        # FIXME test without crapping on filesystem
        self.protocol.answers.append('HiddenServiceDir=/fake/path\n')
        d = tempfile.mkdtemp()

        try:
            with open(os.path.join(d, 'hostname'), 'w') as f:
                f.write('public')
            with open(os.path.join(d, 'private_key'), 'w') as f:
                f.write('private')
            with open(os.path.join(d, 'client_keys'), 'w') as f:
                f.write('client-name hungry\ndescriptor-cookie omnomnom\n')

            conf = TorConfig(self.protocol)
            hs = HiddenService(conf, d, [])

            self.assertEqual(hs.hostname, 'public')
            self.assertEqual(hs.private_key, 'private')
            self.assertEqual(len(hs.client_keys), 1)
            self.assertEqual(hs.client_keys[0].name, 'hungry')
            self.assertEqual(hs.client_keys[0].cookie, 'omnomnom')
            self.assertEqual(hs.client_keys[0].key, None)

        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_onion_keys_stealth(self):
        self.protocol.answers.append('HiddenServiceDir=/fake/path\nHiddenServiceAuthorizeClient=stealth alice,bob,carol\n')
        d = tempfile.mkdtemp()

        try:
            with open(os.path.join(d, 'hostname'), 'w') as f:
                f.write('public')
            with open(os.path.join(d, 'private_key'), 'w') as f:
                f.write('private')
            with open(os.path.join(d, 'client_keys'), 'w') as f:
                f.write('client-name hungry\ndescriptor-cookie omnomnom\n')

            conf = TorConfig(self.protocol)
            hs = HiddenService(conf, d, [])

            self.assertEqual(hs.hostname, 'public')
            self.assertEqual(hs.private_key, 'private')
            self.assertEqual(len(hs.client_keys), 1)
            self.assertEqual(hs.client_keys[0].name, 'hungry')
            self.assertEqual(hs.client_keys[0].cookie, 'omnomnom')
            self.assertEqual(hs.client_keys[0].key, None)

        finally:
            shutil.rmtree(d, ignore_errors=True)

        print(hs.config_attributes())

    @defer.inlineCallbacks
    def test_onion_keys_unknown_auth(self):
        self.protocol.answers.append('HiddenServiceDir=/fake/path\nHiddenServiceAuthorizeClient=bogus_auth_method alice,bob,carol\n')
        d = tempfile.mkdtemp()

        try:
            with open(os.path.join(d, 'hostname'), 'w') as f:
                f.write('public')
            with open(os.path.join(d, 'private_key'), 'w') as f:
                f.write('private')
            with open(os.path.join(d, 'client_keys'), 'w') as f:
                f.write('client-name hungry\ndescriptor-cookie omnomnom\n')

            with self.assertRaises(ValueError) as ctx:
                conf = TorConfig(self.protocol)
                yield conf.post_bootstrap
            self.assertIn(
                "Unknown auth type",
                str(ctx.exception)
            )

        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_single_client(self):
        # FIXME test without crapping on filesystem
        self.protocol.answers.append('HiddenServiceDir=/fake/path\n')
        d = tempfile.mkdtemp()

        try:
            with open(os.path.join(d, 'hostname'), 'w') as f:
                f.write('gobledegook\n')

            conf = TorConfig(self.protocol)
            hs = HiddenService(conf, d, [])

            self.assertEqual(1, len(hs.clients))
            self.assertEqual('default', hs.clients[0][0])
            self.assertEqual('gobledegook', hs.clients[0][1])

        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_single_client_ioerror(self):
        # FIXME test without crapping on filesystem
        self.protocol.answers.append('HiddenServiceDir=/fake/path\n')
        d = tempfile.mkdtemp()

        try:
            with open(os.path.join(d, 'hostname'), 'w') as f:
                f.write('gobledegook\n')
            os.chmod(os.path.join(d, 'hostname'), 0)

            conf = TorConfig(self.protocol)
            hs = HiddenService(conf, d, [])

            self.assertEqual(0, len(hs.clients))

        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_stealth_clients(self):
        # FIXME test without crapping on filesystem
        self.protocol.answers.append('HiddenServiceDir=/fake/path\n')
        d = tempfile.mkdtemp()

        try:
            with open(os.path.join(d, 'hostname'), 'w') as f:
                f.write('oniona cookiea\n')
                f.write('onionb cookieb\n')

            conf = TorConfig(self.protocol)
            hs = HiddenService(conf, d, [])

            self.assertEqual(2, len(hs.clients))
            self.assertEqual('oniona', hs.clients[0][0])
            self.assertEqual('cookiea', hs.clients[0][1])
            self.assertEqual('onionb', hs.clients[1][0])
            self.assertEqual('cookieb', hs.clients[1][1])
            self.assertRaises(RuntimeError, getattr, hs, 'hostname')

        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_modify_hidden_service(self):
        self.protocol.answers.append('HiddenServiceDir=/fake/path\nHiddenServicePort=80 127.0.0.1:1234\n')

        conf = TorConfig(self.protocol)
        conf.hiddenservices[0].version = 3
        self.assertTrue(conf.needs_save())

    def test_add_hidden_service_to_empty_config(self):
        conf = TorConfig()
        h = HiddenService(conf, '/fake/path', ['80 127.0.0.1:1234'], '', 3)
        conf.HiddenServices.append(h)
        self.assertEqual(len(conf.hiddenservices), 1)
        self.assertEqual(h, conf.hiddenservices[0])
        self.assertTrue(conf.needs_save())

    def test_multiple_append(self):
        conf = TorConfig()
        h0 = HiddenService(conf, '/fake/path', ['80 127.0.0.1:1234'], '', 3)
        h1 = HiddenService(conf, '/fake/path', ['90 127.0.0.1:4321'], '', 3)
        h2 = HiddenService(conf, '/fake/path', ['90 127.0.0.1:5432'], '', 3, True)
        conf.hiddenservices = [h0]
        conf.hiddenservices.append(h1)
        conf.hiddenservices.append(h2)
        self.assertEqual(len(conf.hiddenservices), 3)
        self.assertEqual(h0, conf.hiddenservices[0])
        self.assertEqual(h1, conf.hiddenservices[1])
        self.assertEqual(h2, conf.hiddenservices[2])
        self.assertTrue(conf.needs_save())

    def test_hiddenservice_multiple_auth_lines(self):
        fake0 = tempfile.mkdtemp()

        with open(join(fake0, "hostname"), 'w') as f:
            f.write('blarglyfoo.onion cookie # client: bob\n')

        conf = TorConfig(FakeControlProtocol(['config/names=']))
        with self.assertRaises(ValueError) as ctx:
            conf._setup_hidden_services('''HiddenServiceDir={}
HiddenServicePort=80 127.0.0.1:1234
HiddenServiceVersion=2
HiddenServiceAuthorizeClient=basic bob
HiddenServiceAuthorizeClient=stealth alice,jane
'''.format(fake0))
        self.assertIn(
            "Multiple HiddenServiceAuthorizeClient lines",
            str(ctx.exception),
        )

    def test_multiple_startup_services(self):
        fake0 = tempfile.mkdtemp()
        fake1 = tempfile.mkdtemp()

        with open(join(fake0, "hostname"), 'w') as f:
            f.write('blarglyfoo.onion cookie # client: bob\n')

        conf = TorConfig(FakeControlProtocol(['config/names=']))
        conf._setup_hidden_services('''HiddenServiceDir={}
HiddenServicePort=80 127.0.0.1:1234
HiddenServiceVersion=2
HiddenServiceAuthorizeClient=basic bob
HiddenServiceDir={}
HiddenServicePort=80 127.0.0.1:1234
HiddenServicePort=90 127.0.0.1:2345'''.format(fake0, fake1))

        self.assertEqual(len(conf.hiddenservices), 2)

        hs = conf.hiddenservices[0]
        self.assertEqual(hs.hidden_service_directory, fake0)
        self.assertEqual(hs.version, 2)
        self.assertEqual(hs.authorize_client, 'bob cookie')
        self.assertEqual(len(hs.ports), 1)
        self.assertEqual(hs.ports[0], '80 127.0.0.1:1234')

        self.assertEqual(conf.hiddenservices[1].dir, fake1)
        self.assertEqual(len(conf.hiddenservices[1].ports), 2)
        self.assertEqual(conf.hiddenservices[1].ports[0], '80 127.0.0.1:1234')
        self.assertEqual(conf.hiddenservices[1].ports[1], '90 127.0.0.1:2345')

    def test_hidden_service_parse_error(self):
        conf = TorConfig(FakeControlProtocol(['config/names=']))
        try:
            conf._setup_hidden_services('''FakeHiddenServiceKey=foo''')
            self.fail()
        except RuntimeError as e:
            self.assertTrue('parse' in str(e))

    def test_hidden_service_directory_absolute_path(self):
        conf = TorConfig(FakeControlProtocol(['config/names=']))
        conf._setup_hidden_services('HiddenServiceDir=/fake/path/../path')
        self.assertEqual(len(self.flushWarnings()), 1)

    def test_hidden_service_same_directory(self):
        conf = TorConfig(FakeControlProtocol(['config/names=']))
        servicelines = '''HiddenServiceDir=/fake/path
HiddenServiceDir=/fake/path'''
        self.assertRaises(RuntimeError, conf._setup_hidden_services, servicelines)

        conf = TorConfig()
        conf.HiddenServices = [HiddenService(conf, '/fake/path', ['80 127.0.0.1:1234'])]
        conf.HiddenServices.append(HiddenService(conf, '/fake/path', ['80 127.0.0.1:1234']))
        self.assertTrue(conf.needs_save())
        self.assertRaises(RuntimeError, conf.save)

        conf = TorConfig()
        conf.HiddenServices = [HiddenService(conf, '/fake/path', ['80 127.0.0.1:1234'])]
        conf.HiddenServices.append(HiddenService(conf, '/fake/path/two', ['80 127.0.0.1:1234']))
        self.assertTrue(conf.needs_save())
        conf.save()
        conf.hiddenservices[1].dir = '/fake/path'
        self.assertTrue(conf.needs_save())
        self.assertRaises(RuntimeError, conf.save)

    def test_multiple_modify_hidden_service(self):
        self.protocol.answers.append('HiddenServiceDir=/fake/path\nHiddenServicePort=80 127.0.0.1:1234\n')

        conf = TorConfig(self.protocol)
        self.assertTrue(self.protocol.post_bootstrap.called)
        self.assertTrue(conf.post_bootstrap is None or conf.post_bootstrap.called)
        self.assertEqual(len(conf.hiddenservices), 1)
#        self.assertTrue(conf.hiddenservices[0].conf)
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
        self.assertEqual(0, len(conf.hiddenservices[0].authorize_client))
        conf.hiddenservices[0].ports = ['123 127.0.0.1:4321']
        conf.save()

        self.assertTrue(not conf.needs_save())
        conf.hiddenservices[0].ports.append('90 127.0.0.1:2345')
        self.assertTrue(conf.needs_save())


class IteratorTests(unittest.TestCase):
    def test_iterate_torconfig(self):
        cfg = TorConfig()
        cfg.FooBar = 'quux'
        cfg.save()
        cfg.Quux = 'blimblam'

        keys = sorted([k for k in cfg])

        self.assertEqual(['FooBar', 'Quux'], keys)


class LegacyLaunchTorTests(unittest.TestCase):
    """
    Test backwards-compatibility on launch_tor()
    """

    @patch('txtorcon.controller.find_tor_binary', return_value=None)
    @patch('twisted.python.deprecate.warn')
    @defer.inlineCallbacks
    def test_happy_path(self, warn, ftb):
        self.transport = proto_helpers.StringTransport()

        class Connector:
            def __call__(self, proto, trans):
                proto._set_valid_events('STATUS_CLIENT')
                proto.makeConnection(trans)
                proto.post_bootstrap.callback(proto)
                return proto.post_bootstrap

        self.protocol = FakeControlProtocol([])
        trans = Mock()
        trans.protocol = self.protocol
        creator = functools.partial(Connector(), self.protocol, self.transport)
        reactor = Mock()
        config = Mock()
        fake_tor = Mock()
        fake_tor.process = TorProcessProtocol(creator)

        with patch('txtorcon.controller.launch', return_value=fake_tor) as launch:
            directlyProvides(reactor, IReactorCore)
            tpp = yield launch_tor(
                config,
                reactor,
                connection_creator=creator
            )
            self.assertEqual(1, len(launch.mock_calls))
            self.assertTrue(
                isinstance(tpp, TorProcessProtocol)
            )
            self.assertIs(tpp, fake_tor.process)
        calls = warn.mock_calls
        self.assertEqual(1, len(calls))
        self.assertEqual(calls[0][1][1], DeprecationWarning)


class ErrorTests(unittest.TestCase):
    @patch('txtorcon.controller.find_tor_binary', return_value=None)
    @defer.inlineCallbacks
    def test_no_tor_binary(self, ftb):
        self.transport = proto_helpers.StringTransport()

        class Connector:
            def __call__(self, proto, trans):
                proto._set_valid_events('STATUS_CLIENT')
                proto.makeConnection(trans)
                proto.post_bootstrap.callback(proto)
                return proto.post_bootstrap

        self.protocol = FakeControlProtocol([])
        trans = Mock()
        trans.protocol = self.protocol
        creator = functools.partial(Connector(), self.protocol, self.transport)
        reactor = Mock()
        directlyProvides(reactor, IReactorCore)
        try:
            yield launch(
                reactor,
                connection_creator=creator
            )
            self.fail()

        except TorNotFound:
            pass  # success!


# the RSA keys have been shortened below for readability
keydata = '''client-name bar
descriptor-cookie O4rQyZ+IJr2PNHUdeXi0nA==
client-key
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC1R/bPGTWnpGJpNCfT1KIfFq1QEGHz4enKSEKUDkz1CSEPOMGS
bV37dfqTuI4klsFvdUsR3NpYXLin9xRWvw1viKwAN0y8cv5totl4qMxO5i+zcfVh
bJiNvVv2EjfEyQaZfAy2PUfp/tAPYZMsyfps2DptWyNR
-----END RSA PRIVATE KEY-----
client-name foo
descriptor-cookie btlj4+RsWEkxigmlszInhQ==
client-key
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDdLdHU1fbABtFutOFtpdWQdv/9qG1OAc0r1TfaBtkPSNcLezcx
SThalIEnRFfejy0suOHmsqspruvn0FEflIEQvFWeXAPvXg==
-----END RSA PRIVATE KEY-----
client-name quux
descriptor-cookie asdlkjasdlfkjalsdkfffj==
'''


class HiddenServiceAuthTests(unittest.TestCase):

    def test_parse_client_keys(self):
        data = StringIO(keydata)

        clients = list(_parse_client_keys(data))

        self.assertEqual(3, len(clients))
        self.assertEqual('bar', clients[0].name)
        self.assertEqual('O4rQyZ+IJr2PNHUdeXi0nA', clients[0].cookie)
        self.assertEqual('RSA1024:MIICXQIBAAKBgQC1R/bPGTWnpGJpNCfT1KIfFq1QEGHz4enKSEKUDkz1CSEPOMGSbV37dfqTuI4klsFvdUsR3NpYXLin9xRWvw1viKwAN0y8cv5totl4qMxO5i+zcfVhbJiNvVv2EjfEyQaZfAy2PUfp/tAPYZMsyfps2DptWyNR', clients[0].key)

        self.assertEqual('foo', clients[1].name)
        self.assertEqual('btlj4+RsWEkxigmlszInhQ', clients[1].cookie)
        self.assertEqual(clients[1].key, 'RSA1024:MIICXgIBAAKBgQDdLdHU1fbABtFutOFtpdWQdv/9qG1OAc0r1TfaBtkPSNcLezcxSThalIEnRFfejy0suOHmsqspruvn0FEflIEQvFWeXAPvXg==')

        self.assertEqual('quux', clients[2].name)
        self.assertEqual('asdlkjasdlfkjalsdkfffj', clients[2].cookie)
        self.assertEqual(None, clients[2].key)

    def test_parse_error(self):
        data = StringIO('client-name foo\nclient-name xxx\n')

        self.assertRaises(
            RuntimeError,
            _parse_client_keys, data
        )


class LegacyTests(unittest.TestCase):
    """
    This tests that any pre-18.0.0 code for onion/hidden services will
    still work. These can be removed when the deprecated code is gone.
    """

    def setUp(self):
        self.protocol = FakeControlProtocol([])

    @defer.inlineCallbacks
    def test_add_to_tor(self):
        self.protocol.answers.append("ServiceID=asdf\nPrivateKey=blob")
        with warnings.catch_warnings(record=True) as w:
            hs = EphemeralHiddenService(["80 127.0.0.1:1234"])
        d = hs.add_to_tor(self.protocol)
        self.protocol.event_happened('HS_DESC', 'UPLOAD asdf x x x x')
        self.protocol.event_happened('HS_DESC', 'UPLOADED asdf x x x x')
        yield d

        self.assertEqual(hs.hostname, "asdf.onion")
        self.assertEqual(hs.private_key, "blob")
        self.assertIn(
            "deprecated",
            str(w[0].message),
        )

    def test_defaults(self):
        eph = EphemeralHiddenService("80 localhost:80")
        self.assertEqual(eph._ports, ["80,localhost:80"])

    def test_wrong_blob(self):
        wrong_blobs = ["", " ", "foo", ":", " : ", "foo:", ":foo", 0]
        for b in wrong_blobs:
            try:
                EphemeralHiddenService("80 localhost:80", b)
                self.fail("should get exception")
            except ValueError:
                pass

    def test_add(self):
        eph = EphemeralHiddenService("80 127.0.0.1:80")
        proto = Mock()
        proto.queue_command = Mock(return_value="PrivateKey=blam\nServiceID=ohai")
        eph.add_to_tor(proto)

        self.assertEqual("blam", eph.private_key)
        self.assertEqual("ohai.onion", eph.hostname)

    def test_add_keyblob(self):
        eph = EphemeralHiddenService("80 127.0.0.1:80", "alg:blam")
        proto = Mock()
        proto.queue_command = Mock(return_value="ServiceID=ohai")
        eph.add_to_tor(proto)

        self.assertEqual("alg:blam", eph.private_key)
        self.assertEqual("ohai.onion", eph.hostname)

    def test_descriptor_wait(self):
        eph = EphemeralHiddenService("80 127.0.0.1:80")
        proto = FakeControlProtocol(["PrivateKey=blam\nServiceID=ohai\n"])

        eph.add_to_tor(proto)

        proto.event_happened('HS_DESC', 'UPLOADED ohai UNKNOWN somehsdir')
        proto.event_happened('HS_DESC', 'UPLOADED UNKNOWN UNKNOWN somehsdir')

        self.assertEqual("blam", eph.private_key)
        self.assertEqual("ohai.onion", eph.hostname)

    def test_remove(self):
        eph = EphemeralHiddenService("80 127.0.0.1:80")
        eph.hostname = 'foo.onion'
        proto = Mock()
        proto.queue_command = Mock(return_value="OK")

        eph.remove_from_tor(proto)

    @defer.inlineCallbacks
    def test_remove_error(self):
        eph = EphemeralHiddenService("80 127.0.0.1:80")
        eph.hostname = 'foo.onion'
        proto = Mock()
        proto.queue_command = Mock(return_value="it's not ok")

        try:
            yield eph.remove_from_tor(proto)
            self.fail("should have gotten exception")
        except RuntimeError:
            pass

    def test_failed_upload(self):
        eph = EphemeralHiddenService("80 127.0.0.1:80")
        proto = FakeControlProtocol([
            "PrivateKey=seekrit\nServiceID=42\n",
        ])

        d = eph.add_to_tor(proto)

        # Tor leads with UPLOAD events for each attempt; we queue 2 of
        # these...
        proto.event_happened('HS_DESC', 'UPLOAD 42 UNKNOWN hsdir0')
        proto.event_happened('HS_DESC', 'UPLOAD 42 UNKNOWN hsdir1')

        # ...but fail them both
        proto.event_happened('HS_DESC', 'FAILED 42 UNKNOWN hsdir1 REASON=UPLOAD_REJECTED')
        proto.event_happened('HS_DESC', 'FAILED 42 UNKNOWN hsdir0 REASON=UPLOAD_REJECTED')

        self.assertEqual("seekrit", eph.private_key)
        self.assertEqual("42.onion", eph.hostname)
        self.assertTrue(d.called)
        d.addErrback(lambda e: self.assertTrue('Failed to upload' in str(e)))

    def test_single_failed_upload(self):
        eph = EphemeralHiddenService("80 127.0.0.1:80")
        proto = FakeControlProtocol([
            "PrivateKey=seekrit\nServiceID=42\n",
        ])

        d = eph.add_to_tor(proto)

        # Tor leads with UPLOAD events for each attempt; we queue 2 of
        # these...
        proto.event_happened('HS_DESC', 'UPLOAD 42 UNKNOWN hsdir0')
        proto.event_happened('HS_DESC', 'UPLOAD 42 UNKNOWN hsdir1')

        # ...then fail one
        proto.event_happened('HS_DESC', 'FAILED 42 UNKNOWN hsdir1 REASON=UPLOAD_REJECTED')
        # ...and succeed on the last.
        proto.event_happened('HS_DESC', 'UPLOADED 42 UNKNOWN hsdir0')

        self.assertEqual("seekrit", eph.private_key)
        self.assertEqual("42.onion", eph.hostname)
        self.assertTrue(d.called)
