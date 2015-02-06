import datetime
import time
from twisted.trial import unittest
from twisted.internet import defer
from zope.interface import implements

from txtorcon import Circuit
from txtorcon import Stream
from txtorcon import TorControlProtocol
from txtorcon import TorState
from txtorcon import Router
from txtorcon.interface import IRouterContainer
from txtorcon.interface import ICircuitListener
from txtorcon.interface import ICircuitContainer
from txtorcon.interface import CircuitListenerMixin


class FakeTorController(object):
    implements(IRouterContainer, ICircuitListener, ICircuitContainer)

    def __init__(self):
        self.routers = {}
        self.circuits = {}
        self.extend = []
        self.failed = []

    def router_from_id(self, i):
        return self.routers[i[:41]]

    def circuit_new(self, circuit):
        self.circuits[circuit.id] = circuit

    def circuit_extend(self, circuit, router):
        self.extend.append((circuit, router))

    def circuit_launched(self, circuit):
        pass

    def circuit_built(self, circuit):
        pass

    def circuit_closed(self, circuit, **kw):
        if circuit.id in self.circuits:
            del self.circuits[circuit.id]

    def circuit_failed(self, circuit, **kw):
        self.failed.append((circuit, kw))
        if circuit.id in self.circuits:
            del self.circuits[circuit.id]

    def find_circuit(self, circid):
        return self.circuits[circid]

    def close_circuit(self, circid):
        del self.circuits[circid]
        return defer.succeed('')


class FakeLocation:

    def __init__(self):
        self.countrycode = 'NA'


class FakeRouter:

    def __init__(self, hsh, nm):
        self.name = nm
        self.hash = hsh
        self.location = FakeLocation()

examples = ['CIRC 365 LAUNCHED PURPOSE=GENERAL',
            'CIRC 365 EXTENDED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris PURPOSE=GENERAL',
            'CIRC 365 EXTENDED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus PURPOSE=GENERAL',
            'CIRC 365 EXTENDED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus,$253DFF1838A2B7782BE7735F74E50090D46CA1BC=chomsky PURPOSE=GENERAL',
            'CIRC 365 BUILT $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus,$253DFF1838A2B7782BE7735F74E50090D46CA1BC=chomsky PURPOSE=GENERAL',
            'CIRC 365 CLOSED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus,$253DFF1838A2B7782BE7735F74E50090D46CA1BC=chomsky PURPOSE=GENERAL REASON=FINISHED',
            'CIRC 365 FAILED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus,$253DFF1838A2B7782BE7735F74E50090D46CA1BC=chomsky PURPOSE=GENERAL REASON=TIMEOUT']


class CircuitTests(unittest.TestCase):

    def test_age(self):
        """
        make sure age does something sensible at least once.
        """
        tor = FakeTorController()

        circuit = Circuit(tor)
        now = datetime.datetime.now()
        update = '1 LAUNCHED PURPOSE=GENERAL TIME_CREATED=%s' % time.strftime('%Y-%m-%dT%H:%M:%S')
        circuit.update(update.split())
        diff = circuit.age(now=now)
        self.assertEquals(diff, 0)
        self.assertTrue(circuit.time_created is not None)

    def test_no_age_yet(self):
        """
        make sure age doesn't explode if there's no TIME_CREATED flag.
        """
        tor = FakeTorController()

        circuit = Circuit(tor)
        now = datetime.datetime.now()
        circuit.update('1 LAUNCHED PURPOSE=GENERAL'.split())
        self.assertTrue(circuit.time_created is None)
        diff = circuit.age(now=now)
        self.assertEquals(diff, None)

    def test_listener_mixin(self):
        listener = CircuitListenerMixin()
        from zope.interface.verify import verifyObject
        self.assertTrue(verifyObject(ICircuitListener, listener))

        # call all the methods with None for each arg. This is mostly
        # just to gratuitously increase test coverage, but also
        # serves to ensure these methods don't just blow up
        for (methodname, desc) in ICircuitListener.namesAndDescriptions():
            method = getattr(listener, methodname)
            args = [None] * len(desc.positional)
            method(*args)

    def test_unlisten(self):
        tor = FakeTorController()
        tor.routers['$E11D2B2269CC25E67CA6C9FB5843497539A74FD0'] = FakeRouter(
            '$E11D2B2269CC25E67CA6C9FB5843497539A74FD0', 'a'
        )

        circuit = Circuit(tor)
        circuit.listen(tor)
        circuit.listen(tor)
        circuit.update('1 LAUNCHED PURPOSE=GENERAL'.split())
        circuit.unlisten(tor)
        circuit.update('1 EXTENDED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris PURPOSE=GENERAL'.split())
        self.assertEqual(len(tor.circuits), 1)
        self.assertTrue(1 in tor.circuits)
        self.assertEqual(len(tor.extend), 0)
        self.assertEqual(1, len(circuit.path))
        self.assertEqual(0, len(circuit.listeners))

    def test_path_update(self):
        cp = TorControlProtocol()
        state = TorState(cp, False)
        circuit = Circuit(state)
        circuit.update('1 EXTENDED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris PURPOSE=GENERAL'.split())
        self.assertEqual(1, len(circuit.path))
        self.assertEqual(
            '$E11D2B2269CC25E67CA6C9FB5843497539A74FD0',
            circuit.path[0].id_hex
        )
        self.assertEqual('eris', circuit.path[0].name)

    def test_wrong_update(self):
        tor = FakeTorController()
        circuit = Circuit(tor)
        circuit.listen(tor)
        circuit.update('1 LAUNCHED PURPOSE=GENERAL'.split())
        self.assertRaises(
            Exception,
            circuit.update,
            '2 LAUNCHED PURPOSE=GENERAL'.split()
        )

    def test_closed_remaining_streams(self):
        tor = FakeTorController()
        circuit = Circuit(tor)
        circuit.listen(tor)
        circuit.update('1 LAUNCHED PURPOSE=GENERAL'.split())
        stream = Stream(tor)
        stream.update("1 NEW 0 94.23.164.42.$43ED8310EB968746970896E8835C2F1991E50B69.exit:9001 SOURCE_ADDR=(Tor_internal):0 PURPOSE=DIR_FETCH".split())
        circuit.streams.append(stream)
        self.assertEqual(len(circuit.streams), 1)

        circuit.update('1 CLOSED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus,$253DFF1838A2B7782BE7735F74E50090D46CA1BC=chomsky PURPOSE=GENERAL REASON=FINISHED'.split())
        circuit.update('1 FAILED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus,$253DFF1838A2B7782BE7735F74E50090D46CA1BC=chomsky PURPOSE=GENERAL REASON=TIMEOUT'.split())
        errs = self.flushLoggedErrors()
        self.assertEqual(len(errs), 2)

    def test_updates(self):
        tor = FakeTorController()
        circuit = Circuit(tor)
        circuit.listen(tor)
        tor.routers['$E11D2B2269CC25E67CA6C9FB5843497539A74FD0'] = FakeRouter(
            '$E11D2B2269CC25E67CA6C9FB5843497539A74FD0', 'a'
        )
        tor.routers['$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5'] = FakeRouter(
            '$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5', 'b'
        )
        tor.routers['$253DFF1838A2B7782BE7735F74E50090D46CA1BC'] = FakeRouter(
            '$253DFF1838A2B7782BE7735F74E50090D46CA1BC', 'c'
        )

        for ex in examples[:-1]:
            circuit.update(ex.split()[1:])
            self.assertEqual(circuit.state, ex.split()[2])
            self.assertEqual(circuit.purpose, 'GENERAL')
            if '$' in ex:
                self.assertEqual(
                    len(circuit.path),
                    len(ex.split()[3].split(','))
                )
                for (r, p) in zip(ex.split()[3].split(','), circuit.path):
                    d = r.split('=')[0]
                    self.assertEqual(d, p.hash)

    def test_extend_messages(self):
        tor = FakeTorController()
        a = FakeRouter('$E11D2B2269CC25E67CA6C9FB5843497539A74FD0', 'a')
        b = FakeRouter('$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5', 'b')
        c = FakeRouter('$253DFF1838A2B7782BE7735F74E50090D46CA1BC', 'c')
        tor.routers['$E11D2B2269CC25E67CA6C9FB5843497539A74FD0'] = a
        tor.routers['$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5'] = b
        tor.routers['$253DFF1838A2B7782BE7735F74E50090D46CA1BC'] = c

        circuit = Circuit(tor)
        circuit.listen(tor)

        circuit.update('365 LAUNCHED PURPOSE=GENERAL'.split())
        self.assertEqual(tor.extend, [])
        circuit.update('365 EXTENDED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris PURPOSE=GENERAL'.split())
        self.assertEqual(len(tor.extend), 1)
        self.assertEqual(tor.extend[0], (circuit, a))

        circuit.update('365 EXTENDED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus PURPOSE=GENERAL'.split())
        self.assertEqual(len(tor.extend), 2)
        self.assertEqual(tor.extend[0], (circuit, a))
        self.assertEqual(tor.extend[1], (circuit, b))

        circuit.update('365 EXTENDED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus,$253DFF1838A2B7782BE7735F74E50090D46CA1BC=chomsky PURPOSE=GENERAL'.split())
        self.assertEqual(len(tor.extend), 3)
        self.assertEqual(tor.extend[0], (circuit, a))
        self.assertEqual(tor.extend[1], (circuit, b))
        self.assertEqual(tor.extend[2], (circuit, c))

    def test_extends_no_path(self):
        '''
        without connectivity, it seems you get EXTENDS messages with no
        path update.
        '''
        tor = FakeTorController()
        circuit = Circuit(tor)
        circuit.listen(tor)

        circuit.update('753 EXTENDED BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME PURPOSE=MEASURE_TIMEOUT TIME_CREATED=2012-07-30T18:23:18.956704'.split())
        self.assertEqual(tor.extend, [])
        self.assertEqual(circuit.path, [])
        self.assertTrue('IS_INTERNAL' in circuit.build_flags)
        self.assertTrue('NEED_CAPACITY' in circuit.build_flags)
        self.assertTrue('NEED_UPTIME' in circuit.build_flags)

    def test_str(self):
        tor = FakeTorController()
        circuit = Circuit(tor)
        circuit.id = 1
        str(circuit)
        router = Router(tor)
        circuit.path.append(router)
        str(circuit)

    def test_failed_reason(self):
        tor = FakeTorController()
        circuit = Circuit(tor)
        circuit.listen(tor)
        circuit.update('1 FAILED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris PURPOSE=GENERAL REASON=TIMEOUT'.split())
        self.assertEqual(len(tor.failed), 1)
        circ, kw = tor.failed[0]
        self.assertEqual(circ, circuit)
        self.assertTrue('PURPOSE' in kw)
        self.assertTrue('REASON' in kw)
        self.assertEqual(kw['PURPOSE'], 'GENERAL')
        self.assertEqual(kw['REASON'], 'TIMEOUT')

    def test_close_circuit(self):
        tor = FakeTorController()
        a = FakeRouter('$E11D2B2269CC25E67CA6C9FB5843497539A74FD0', 'a')
        b = FakeRouter('$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5', 'b')
        c = FakeRouter('$253DFF1838A2B7782BE7735F74E50090D46CA1BC', 'c')
        tor.routers['$E11D2B2269CC25E67CA6C9FB5843497539A74FD0'] = a
        tor.routers['$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5'] = b
        tor.routers['$253DFF1838A2B7782BE7735F74E50090D46CA1BC'] = c

        circuit = Circuit(tor)
        circuit.listen(tor)

        circuit.update('123 EXTENDED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus,$253DFF1838A2B7782BE7735F74E50090D46CA1BC=chomsky PURPOSE=GENERAL'.split())

        self.assertEqual(3, len(circuit.path))
        d = circuit.close()
        # we already pretended that Tor answered "OK" to the
        # CLOSECIRCUIT call (see close_circuit() in FakeTorController
        # above) however the circuit isn't "really" closed yet...
        self.assertTrue(not d.called)
        # not unit-test-y? shouldn't probably delve into internals I
        # suppose...
        self.assertTrue(circuit._closing_deferred is not None)

        # simulate that Tor has really closed the circuit for us
        # this should cause our Deferred to callback
        circuit.update('123 CLOSED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus,$253DFF1838A2B7782BE7735F74E50090D46CA1BC=chomsky PURPOSE=GENERAL REASON=FINISHED'.split())

        # confirm that our circuit callback has been triggered already
        self.assertRaises(
            defer.AlreadyCalledError,
            d.callback,
            "should have been called already"
        )
        return d
