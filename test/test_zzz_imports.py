from twisted.trial import unittest

import gc
import sys
import types
import functools
from unittest import skipIf


def fake_import(orig, name, *args, **kw):
    if name in ['GeoIP', 'ipaddr', 'stem']:
        raise ImportError('testing!')
    return orig(*((name,) + args), **kw)


class TestImports(unittest.TestCase):
    # XXX FIXME this messes up "os" imports, of all things, for some
    # reason, so it gets the "zzz" in its name to be "last". But
    # that's not a very good solution.

    @skipIf('pypy' in sys.version.lower(), "Doesn't work in PYPY")
    def test_no_GeoIP(self):
        """
        Make sure we don't explode if there's no GeoIP module
        """

        global __builtins__
        orig = __builtins__['__import__']
        try:
            # attempt to ensure we've unimportted txtorcon.util
            try:
                del sys.modules['txtorcon.util']
            except KeyError:
                pass
            import gc
            gc.collect()

            # replace global import with our test import, which will
            # throw on GeoIP import no matter what
            __builtins__['__import__'] = functools.partial(fake_import, orig)

            # now ensure we set up all the databases as "None" when we
            # import w/o the GeoIP thing available.
            import txtorcon.util
            ipa = txtorcon.util.maybe_ip_addr('127.0.0.1')
            self.assertTrue(isinstance(ipa, types.StringType))

        finally:
            __builtins__['__import__'] = orig

    @skipIf('pypy' in sys.version.lower(), "Doesn't work in PYPY")
    def test_no_ipaddr(self):
        """
        make sure the code we run if there's no ipaddr installed
        doesn't do anything horrific
        """

        global __builtins__
        orig = __builtins__['__import__']
        try:
            # attempt to ensure we've unimportted txtorcon.util
            try:
                del sys.modules['txtorcon.util']
                gc.collect()
            except KeyError:
                pass
            __builtins__['__import__'] = functools.partial(fake_import, orig)

            # now ensure we set up all the databases as "None" when we
            # import w/o the GeoIP thing available.
            import txtorcon.util
            self.assertEqual(None, txtorcon.util.city)
            self.assertEqual(None, txtorcon.util.asn)
            self.assertEqual(None, txtorcon.util.country)

        finally:
            __builtins__['__import__'] = orig

    @skipIf('pypy' in sys.version.lower(), "Doesn't work in PYPY")
    def test_no_Stem(self):
        """
        Ensure we work without Stem installed
        """

        global __builtins__
        orig = __builtins__['__import__']
        try:
            # attempt to ensure we've unimportted txtorcon.util
            try:
                del sys.modules['txtorcon.torcontrolprotocol']
            except KeyError:
                pass
            import gc
            gc.collect()

            __builtins__['__import__'] = functools.partial(fake_import, orig)

            # make sure we marked that we don't have Stem
            import txtorcon.torcontrolprotocol
            self.assertFalse(txtorcon.torcontrolprotocol._HAVE_STEM)

        finally:
            __builtins__['__import__'] = orig
