
import txtorcon.spaghetti
from txtorcon.spaghetti import *
from twisted.trial import unittest

import tempfile
import os

class FsmTests(unittest.TestCase):

    def match(self, data):
        if data.split()[0] == '250':
            return True
        return False

    def test_reprs(self):
        """
        not really 'testing' here, going for code-coverage to simply
        call the __str__ methods to ensure they don't explode
        """
        
        a = State("A")
        b = State("B")
        def match(x):
            pass
        def action(x):
            pass
        tran = Transition(b, match, action)
        a.add_transition(tran)
        fsm = FSM([a, b])
        x = str(fsm)
        x = str(a)
        x = str(tran)
        tran.start_state = None
        x = str(tran)
        x = fsm.dotty()

    def test_no_init(self):
        fsm = FSM([])
        self.assertRaises(Exception, fsm.process, "")
    
    def test_no_init_ctor(self):
        fsm = FSM([])
        idle = State("I")
        foo = str(idle)
        
        fsm.add_state(idle)
        self.assertWarns(RuntimeWarning, "No next state", txtorcon.spaghetti.__file__,
                         fsm.process, "")
    
    def test_no_matcher(self):
        idle = State("I")
        other = State("O")
        fsm = FSM([idle, other])

        idle.add_transition(Transition(other, None, None))
        fsm.process("")

    def test_bad_transition(self):
        self.assertRaises(Exception, Transition, None, self.match, None)
        
    def test_dotty(self):
        idle = State("I")
        fsm = FSM([idle])
        self.assertTrue(idle.dotty() in fsm.dotty())
        self.assertTrue("digraph" in fsm.dotty())
        fname = tempfile.mktemp() + '.dot'
        open(fname, 'w').write(fsm.dotty())
        self.assertEqual(os.system("dot %s > /dev/null" % fname), 0)
        os.unlink(fname)

    def test_handler_state(self):
        idle = State("I")
        cmd = State("C")
        def handler(x):
            return idle

        idle.add_transitions([Transition(cmd,
                                         self.match,
                                         handler)])
        
        fsm = FSM([idle, cmd])
        self.commands = []
        self.assertEqual(fsm.state, idle)
        fsm.process("250 OK\n")
        self.assertEqual(fsm.state, idle)
    
    def test_simple_machine(self):
        idle = State("I")
        cmd = State("C")

        idle.add_transitions([Transition(cmd,
                                         self.match,
                                         None)])
        
        fsm = FSM([idle, cmd])
        self.commands = []
        self.assertEqual(fsm.state, idle)
        fsm.process("250 OK\n")
        self.assertEqual(fsm.state, cmd)

    def doCommand(self, data):
        print "transition:",data
