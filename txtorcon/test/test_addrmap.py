
import time
import datetime
from twisted.trial import unittest
from twisted.internet import reactor, task
from twisted.internet.interfaces import IReactorTime
from zope.interface import implements

# outside this package, you can do
# from txtorcon import Circuit
from txtorcon.addrmap import AddrMap
from txtorcon.addrmap import Addr
from txtorcon.interface import IAddrListener

class AddrMapTests(unittest.TestCase):
    implements(IAddrListener)

    fmt = '%Y-%m-%d %H:%M:%S'

    def test_parse(self):
        """
        Make sure it's parsing things properly.
        """
        
        now = datetime.datetime.now() + datetime.timedelta(seconds=10)
        nowutc = datetime.datetime.utcnow() + datetime.timedelta(seconds=10)
        ## we need to not-barf on extra args as per control-spec.txt
        line = 'www.example.com 72.30.2.43 "%s" EXPIRES="%s" FOO=bar BAR=baz' % (now.strftime(self.fmt), nowutc.strftime(self.fmt))
        am = AddrMap()
        am.update(line)
        addr = am.find('www.example.com')
        
        self.assertTrue(addr.ip.exploded == '72.30.2.43')
        ## maybe not the most robust, should convert to
        ## seconds-since-epoch instead? the net result of the parsing
        ## is we've rounded to seconds...
        self.assertEqual(addr.expires.ctime(), nowutc.ctime())

        ## this will have resulted in an expiry call, which we need to
        ## cancel to keep the reactor clean. for consistency, we use
        ## the IReactorTime interface from AddrMap
        am.scheduler.getDelayedCalls()[0].cancel()

    def test_expires(self):
        """
        Test simply expiry case
        """
        
        clock = task.Clock()
        am = AddrMap()
        am.scheduler = IReactorTime(clock)
        
        now = datetime.datetime.now() + datetime.timedelta(seconds=10)
        nowutc = datetime.datetime.utcnow() + datetime.timedelta(seconds=10)
        line = 'www.example.com 72.30.2.43 "%s" EXPIRES="%s"' % (now.strftime(self.fmt), nowutc.strftime(self.fmt))
        
        am.update(line)

        self.assertTrue(am.addr.has_key('www.example.com'))
        ## advance time past when the expiry should have occurred
        clock.advance(10)
        self.assertTrue(not am.addr.has_key('www.example.com'))

    def test_expires_never(self):
        """
        Test a NEVER expires line, as in what we'd get a startup for a
        configured address-mapping.
        """
        
        clock = task.Clock()
        am = AddrMap()
        am.scheduler = IReactorTime(clock)
        
        now = datetime.datetime.now() + datetime.timedelta(seconds=10)
        nowutc = datetime.datetime.utcnow() + datetime.timedelta(seconds=10)
        line = 'www.example.com 72.30.2.43 "NEVER"'
        
        am.update(line)

        self.assertTrue(am.addr.has_key('www.example.com'))
        self.assertEqual(len(clock.getDelayedCalls()), 0)

    def test_expires_old(self):
        """
        Test something that expires before "now"
        """
        
        clock = task.Clock()
        am = AddrMap()
        am.scheduler = IReactorTime(clock)
        
        now = datetime.datetime.now() + datetime.timedelta(seconds=-10)
        nowutc = datetime.datetime.utcnow() + datetime.timedelta(seconds=-10)
        line = 'www.example.com 72.30.2.43 "%s" EXPIRES="%s"' % (now.strftime(self.fmt), nowutc.strftime(self.fmt))

        am.update(line)
        self.assertTrue(am.addr.has_key('www.example.com'))
        ## arguably we shouldn't even have put this in the map maybe,
        ## but the reactor needs to iterate before our expiry callback
        ## gets called (right away) which is simulated by the
        ## clock.advance call
        clock.advance(0)
        self.assertTrue(not am.addr.has_key('www.example.com'))

    def test_expires_with_update(self):
        """
        This test updates the expiry time and checks that we properly
        delay our expiry callback.
        """
        clock = task.Clock()
        am = AddrMap()
        am.scheduler = IReactorTime(clock)
        
        ## now do an actual update to an existing Addr entry.
        now = datetime.datetime.now() + datetime.timedelta(seconds=10)
        nowutc = datetime.datetime.utcnow() + datetime.timedelta(seconds=10)
        line = 'www.example.com 72.30.2.43 "%s" EXPIRES="%s"' % (now.strftime(self.fmt), nowutc.strftime(self.fmt))
        am.update(line)
        self.assertTrue(am.find('www.example.com'))

        ## the update
        now = datetime.datetime.now() + datetime.timedelta(seconds=20)
        nowutc = datetime.datetime.utcnow() + datetime.timedelta(seconds=20)
        line = 'www.example.com 72.30.2.43 "%s" EXPIRES="%s"' % (now.strftime(self.fmt), nowutc.strftime(self.fmt))
        am.update(line)
        self.assertTrue(am.addr.has_key('www.example.com'))

        ## advance time by the old expiry value and we should still
        ## find the entry
        clock.advance(10)
        self.assertTrue(am.addr.has_key('www.example.com'))

        ## ...but advance past the new expiry (another 10 seconds) and
        ## it should vanish
        clock.advance(10)
        self.assertTrue(not am.addr.has_key('www.example.com'))

    def addrmap_expired(self, name):
        self.expires.append(name)

    def addrmap_added(self, addr):
        self.addrmap.append(addr)

    def test_listeners(self):
        self.expires = []
        self.addrmap = []

        clock = task.Clock()
        am = AddrMap()
        am.scheduler = IReactorTime(clock)
        am.add_listener(self)

        now = datetime.datetime.now() + datetime.timedelta(seconds=10)
        nowutc = datetime.datetime.utcnow() + datetime.timedelta(seconds=10)
        line = 'www.example.com 72.30.2.43 "%s" EXPIRES="%s"' % (now.strftime(self.fmt), nowutc.strftime(self.fmt))

        am.update(line)

        ## see if our listener got an update
        a = am.find('www.example.com')
        self.assertEqual(self.addrmap, [a])

        ## advance time past when the expiry should have occurred
        clock.advance(10)

        ## check that our listener got an expires event
        self.assertEqual(self.expires, ['www.example.com'])
