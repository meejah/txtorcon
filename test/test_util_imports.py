from twisted.trial import unittest

import sys
import functools


def fake_import(orig, name, *args, **kw):
    ##print "IMPORTING", name
    if 'GeoIP' in name:
        raise ImportError('testing!')
    return orig(*((name,) + args), **kw)

class TestImports(unittest.TestCase):

    def _test_no_GeoIP(self):
        ## make sure the code we run if there's no GeoIP installed
        ## doesn't do anything horrific
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
            import txtorcon.util

            # now ensure that we did the right thing when the GeoIP
            # import failed, which means we should have used pygeoip.GeoIP
            import pygeoip
            self.assertEqual(txtorcon.util.create_geoip, pygeoip.GeoIP)

        finally:
            __import__ = orig
