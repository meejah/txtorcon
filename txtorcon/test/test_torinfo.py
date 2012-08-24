import os
import shutil
import tempfile
import functools

from zope.interface import implements
from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.internet import defer, error
from twisted.python.failure import Failure

from txtorcon import TorControlProtocol, ITorControlProtocol, TorInfo

class FakeControlProtocol:
    """
    """
    
    implements(ITorControlProtocol)

    def __init__(self, answers):
        self.answers = answers
        self.post_bootstrap = defer.succeed(self)

    def get_info_raw(self, info):
        if len(self.answers) == 0:
            d = defer.Deferred()
            self.pending.append(d)
            return d

        d = defer.succeed(self.answers[0])
        self.answers = self.answers[1:]
        return d
    get_info = get_info_raw

class CheckAnswer:
    def __init__(self, test, ans):
        self.answer = ans
        self.test = test

    def __call__(self, x):
        self.test.assertEqual(x, self.answer)

class MagicContainerTests(unittest.TestCase):

    def test_repr(self):
        from txtorcon.torinfo import MagicContainer
        m = MagicContainer('foo')
        self.assertTrue(repr(m) == 'foo')
        self.assertTrue(str(m) == 'foo')
        
        m._setup_complete()
        self.assertTrue(repr(m) == 'foo')
        self.assertTrue(str(m) == 'foo')
        
    
class InfoTests(unittest.TestCase):

    def setUp(self):
        self.protocol = FakeControlProtocol([])

    def test_simple(self):
        self.protocol.answers.append('''info/names=
something a documentation string
multi/path a documentation string
''')
        info = TorInfo(self.protocol)
        self.assertTrue(hasattr(info, 'something'))
        self.assertTrue(hasattr(info, 'multi'))
        self.assertTrue(hasattr(getattr(info,'multi'), 'path'))

        self.protocol.answers.append('something=\nfoo\nOK')

        d = info.something()
        d.addCallback(CheckAnswer(self, 'foo'))
        return d

    def test_same_prefix(self):
        self.protocol.answers.append('''info/names=
something/one a documentation string
something/two a second documentation string
''')
        info = TorInfo(self.protocol)

        self.assertTrue(hasattr(info,'something'))
        self.assertTrue(hasattr(info.something, 'one'))
        self.assertTrue(hasattr(info.something, 'two'))

        self.protocol.answers.append('something/two=bar\nOK')

        d = info.something.two()
        d.addCallback(CheckAnswer(self, 'bar'))
        return d

    def test_attribute_access(self):
        '''
        test that our post-setup TorInfo pretends to only have
        attributes that correspond to (valid) GETINFO calls.
        '''

        self.protocol.answers.append('''info/names=
something/one a documentation string
something/two a second documentation string
''')
        info = TorInfo(self.protocol)

        self.assertTrue(dir(info) == ['something'])
        self.assertTrue(dir(info.something) == ['one', 'two'] or \
                        dir(info.something) == ['two', 'one'])

    def test_iterator_access(self):
        '''
        confirm we can use the iterator protocol
        '''

        self.protocol.answers.append('''info/names=
something/one a documentation string
something/two a second documentation string
''')
        info = TorInfo(self.protocol)

        self.assertTrue(len(info) == 1)
        all = []
        for x in info:
            all.append(x)
        self.assertTrue(len(all) == 1)

        self.assertTrue(len(info.something) == 2)
        all = []
        for x in info.something:
            all.append(x)
        self.assertTrue(len(all) == 2)

    def handle_error(self, f):
        if 'Already had something' in f.getErrorMessage():
            self.error_happened = True

    def test_prefix_error(self):
        self.protocol.answers.append('''info/names=
something not allowed I hope    
something/one a documentation string
''')
        self.error_happened = False
        info = TorInfo(self.protocol, self.handle_error)
        self.assertTrue(self.error_happened)

    def test_prefix_error_other_order(self):
        self.protocol.answers.append('''info/names=
other/one a documentation string
other not allowed I hope    
''')
        self.error_happened = False
        info = TorInfo(self.protocol, self.handle_error)
        self.assertTrue(self.error_happened)

    def test_with_arg(self):
        self.protocol.answers.append('''info/names=
multi/path/arg/* a documentation string
''')
        info = TorInfo(self.protocol)
        self.assertTrue(hasattr(info, 'multi'))
        self.assertTrue(hasattr(getattr(info,'multi'), 'path'))
        self.assertTrue(hasattr(getattr(getattr(info,'multi'), 'path'), 'arg'))

        self.protocol.answers.append('multi/path/arg/quux=\nbar\nbaz\nquux\nOK')

        try:
            info.multi.path.arg()
            self.assertTrue(False)
        except TypeError, e:
            pass
        
        d = info.multi.path.arg('quux')
        d.addCallback(CheckAnswer(self, 'bar\nbaz\nquux'))
        return d

    def test_with_arg_error(self):
        self.protocol.answers.append('''info/names=
multi/no-arg docstring
''')
        info = TorInfo(self.protocol)
    
        try:
            info.multi.no_arg('an argument')
            self.assertTrue(False)
        except TypeError, e:
            pass

    def test_dump(self):
        self.protocol.answers.append('''info/names=
multi/path/arg/* a documentation string
''')
        info = TorInfo(self.protocol)
        info.dump()

    def test_config_star_workaround(self):
        '''
        ensure we ignore config/* for now
        '''
        
        self.protocol.answers.append('''info/names=
config/* a documentation string
''')
        info = TorInfo(self.protocol)
        self.assertTrue(dir(info) == [])

    def test_other_bootstrap(self):
        self.protocol.answers.append('''info/names=
multi/path/arg/* a documentation string
''')
        self.protocol.post_bootstrap = None
        info = TorInfo(self.protocol)

    def test_str(self):
        '''rather silly test to cover string creation'''
        self.protocol.answers.append('''info/names=
version docstring
foo/* bar
''')
        info = TorInfo(self.protocol)

        ## not the end of the world if this fails
        self.assertTrue(str(info.version) == "version()")
        self.assertTrue(str(info.foo) == "foo(arg)")
