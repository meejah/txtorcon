
from twisted.trial import unittest
from zope.interface import implements

from txtorcon import Circuit, Stream
from txtorcon.interface import IRouterContainer, ICircuitListener, ICircuitContainer

class FakeTorController(object):
    implements(IRouterContainer, ICircuitListener, ICircuitContainer)
    
    def __init__(self):
        self.routers = {}
        self.circuits = {}
        self.extend = []
        self.failed = []
    def router_from_id(self, i):
        return self.routers[i]
    def circuit_new(self, circuit):
        self.circuits[circuit.id] = circuit
    def circuit_extend(self, circuit, router):
        self.extend.append((circuit, router))
    def circuit_launched(self, circuit):
        pass
    def circuit_built(self, circuit):
        pass
    def circuit_closed(self, circuit):
        if self.circuits.has_key(circuit.id):
            del self.circuits[circuit.id]
    def circuit_failed(self, circuit, reason):
        self.failed.append((circuit,reason))
        if self.circuits.has_key(circuit.id):
            del self.circuits[circuit.id]
    def find_circuit(self, circid):
        return self.circuits[circid]
        
class FakeLocation:
    def __init__(self):
        self.countrycode = 'NA'
class FakeRouter:
    def __init__(self, hsh, nm):
        self.name = nm
        self.hash = hsh
        self.location = FakeLocation()

examples = [
    'CIRC 365 LAUNCHED PURPOSE=GENERAL',
    'CIRC 365 EXTENDED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris PURPOSE=GENERAL',
    'CIRC 365 EXTENDED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus PURPOSE=GENERAL',
    'CIRC 365 EXTENDED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus,$253DFF1838A2B7782BE7735F74E50090D46CA1BC=chomsky PURPOSE=GENERAL',
    'CIRC 365 BUILT $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus,$253DFF1838A2B7782BE7735F74E50090D46CA1BC=chomsky PURPOSE=GENERAL',
    'CIRC 365 CLOSED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus,$253DFF1838A2B7782BE7735F74E50090D46CA1BC=chomsky PURPOSE=GENERAL REASON=FINISHED',

    'CIRC 365 FAILED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris,$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5=venus,$253DFF1838A2B7782BE7735F74E50090D46CA1BC=chomsky PURPOSE=GENERAL REASON=TIMEOUT'
    ]

class CircuitTests(unittest.TestCase):

    def test_unlisten(self):
        tor = FakeTorController()
        tor.routers['$E11D2B2269CC25E67CA6C9FB5843497539A74FD0'] = FakeRouter('$E11D2B2269CC25E67CA6C9FB5843497539A74FD0','a')
        
        circuit = Circuit(tor)
        circuit.listen(tor)
        circuit.update('1 LAUNCHED PURPOSE=GENERAL'.split())
        circuit.unlisten(tor)
        circuit.update('1 EXTENDED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris PURPOSE=GENERAL'.split())
        self.assertEqual(len(tor.circuits), 1)
        self.assertTrue(tor.circuits.has_key(1))
        self.assertEqual(len(tor.extend), 0)
        
    def test_wrong_update(self):
        tor = FakeTorController()
        circuit = Circuit(tor)
        circuit.listen(tor)
        circuit.update('1 LAUNCHED PURPOSE=GENERAL'.split())
        self.assertRaises(Exception, circuit.update, '2 LAUNCHED PURPOSE=GENERAL'.split())

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
        tor.routers['$E11D2B2269CC25E67CA6C9FB5843497539A74FD0'] = FakeRouter('$E11D2B2269CC25E67CA6C9FB5843497539A74FD0','a')
        tor.routers['$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5'] = FakeRouter('$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5','b')
        tor.routers['$253DFF1838A2B7782BE7735F74E50090D46CA1BC'] = FakeRouter('$253DFF1838A2B7782BE7735F74E50090D46CA1BC','c')

        for ex in examples[:-1]:
            circuit.update(ex.split()[1:])
            self.assertEqual(circuit.state, ex.split()[2])
            self.assertEqual(circuit.purpose, 'GENERAL')

            if '$' in ex:
                self.assertEqual(len(circuit.path), len(ex.split()[3].split(',')))
                for (r,p) in zip(ex.split()[3].split(','), circuit.path):
                    d = r.split('=')[0]
                    self.assertEqual(d, p.hash)

    def test_extend_messages(self):
        tor = FakeTorController()
        a = FakeRouter('$E11D2B2269CC25E67CA6C9FB5843497539A74FD0','a')
        b = FakeRouter('$50DD343021E509EB3A5A7FD0D8A4F8364AFBDCB5','b')
        c = FakeRouter('$253DFF1838A2B7782BE7735F74E50090D46CA1BC','c')
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
        without connectivity, it seems you get EXTENDS messages with no path update.
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
        foo = str(circuit)

    def test_failed_reason(self):
        tor = FakeTorController()
        circuit = Circuit(tor)
        circuit.listen(tor)
        circuit.update('1 FAILED $E11D2B2269CC25E67CA6C9FB5843497539A74FD0=eris PURPOSE=GENERAL REASON=TIMEOUT'.split())
        self.assertEqual(len(tor.failed), 1)
        self.assertEqual(tor.failed[0], (circuit, 'TIMEOUT'))
