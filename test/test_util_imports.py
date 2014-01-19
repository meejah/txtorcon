from twisted.trial import unittest

import sys
import functools


def fake_import(orig, name, *args, **kw):
    ##print "IMPORTING", name
    if 'GeoIP' in name:
        raise ImportError('testing!')
    return orig(*((name,) + args), **kw)


class TestImports(unittest.TestCase):

    def test_no_GeoIP(self):
        """
        make sure the code we run if there's no GeoIP installed
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
