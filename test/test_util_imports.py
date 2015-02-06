from twisted.trial import unittest

import sys
import types
import functools
from unittest import skipIf


def fake_import(orig, name, *args, **kw):
    if name in ['GeoIP', 'ipaddr']:
        raise ImportError('testing!')
    return orig(*((name,) + args), **kw)


class TestImports(unittest.TestCase):

    @skipIf('pypy' in sys.version.lower(), "Doesn't work in PYPY")
    def test_no_GeoIP(self):
        """
        Make sure we don't explode if there's no GeoIP module
        """

        global __import__
        orig = __import__
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
            global __builtins__
            __builtins__['__import__'] = functools.partial(fake_import, orig)

            # now ensure we set up all the databases as "None" when we
            # import w/o the GeoIP thing available.
            import txtorcon.util
            ipa = txtorcon.util.maybe_ip_addr('127.0.0.1')
            self.assertTrue(isinstance(ipa, types.StringType))

        finally:
            __import__ = orig

    @skipIf('pypy' in sys.version.lower(), "Doesn't work in PYPY")
    def test_no_ipaddr(self):
        """
        make sure the code we run if there's no ipaddr installed
        doesn't do anything horrific
        """

        global __import__
        orig = __import__
        try:
            # attempt to ensure we've unimportted txtorcon.util
            del sys.modules['txtorcon.util']
            import gc
            gc.collect()

            # replace global import with our test import, which will
            # throw on GeoIP import no matter what
            global __builtins__
            __builtins__['__import__'] = functools.partial(fake_import, orig)

            # now ensure we set up all the databases as "None" when we
            # import w/o the GeoIP thing available.
            import txtorcon.util
            self.assertEqual(None, txtorcon.util.city)
            self.assertEqual(None, txtorcon.util.asn)
            self.assertEqual(None, txtorcon.util.country)

        finally:
            __import__ = orig
