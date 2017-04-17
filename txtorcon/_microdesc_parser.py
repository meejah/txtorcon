
from .util import find_keywords
import automat


# putting the old parser back in here for now until there's a solution
# making Automat faster
from .spaghetti import FSM, State, Transition


class MicrodescriptorParser(object):
    """
    Parsers microdescriptors line by line. New relays are emitted via
    the 'create_relay' callback.
    """

    def __init__(self, create_relay):
        self._create_relay = create_relay
        self._relay_attrs = None

        class die(object):
            __name__ = 'die'  # FIXME? just to ease spagetti.py:82's pain

            def __init__(self, msg):
                self.msg = msg

            def __call__(self, *args):
                raise RuntimeError(self.msg % tuple(args))

        waiting_r = State("waiting_r")
        waiting_w = State("waiting_w")
        waiting_p = State("waiting_p")
        waiting_s = State("waiting_s")

        def ignorable_line(x):
            x = x.strip()
            return x in ['.', 'OK', ''] or x.startswith('ns/')

        waiting_r.add_transition(Transition(waiting_r, ignorable_line, None))
        waiting_r.add_transition(Transition(waiting_s, lambda x: x.startswith('r '), self._router_begin))
        # FIXME use better method/func than die!!
        waiting_r.add_transition(Transition(waiting_r, lambda x: not x.startswith('r '), die('Expected "r " while parsing routers not "%s"')))

        waiting_s.add_transition(Transition(waiting_w, lambda x: x.startswith('s '), self._router_flags))
        waiting_s.add_transition(Transition(waiting_s, lambda x: x.startswith('a '), self._router_address))
        waiting_s.add_transition(Transition(waiting_r, ignorable_line, None))
        waiting_s.add_transition(Transition(waiting_r, lambda x: not x.startswith('s ') and not x.startswith('a '), die('Expected "s " while parsing routers not "%s"')))
        waiting_s.add_transition(Transition(waiting_r, lambda x: x.strip() == '.', None))

        waiting_w.add_transition(Transition(waiting_p, lambda x: x.startswith('w '), self._router_bandwidth))
        waiting_w.add_transition(Transition(waiting_r, ignorable_line, None))
        waiting_w.add_transition(Transition(waiting_s, lambda x: x.startswith('r '), self._router_begin))  # "w" lines are optional
        waiting_w.add_transition(Transition(waiting_r, lambda x: not x.startswith('w '), die('Expected "w " while parsing routers not "%s"')))
        waiting_w.add_transition(Transition(waiting_r, lambda x: x.strip() == '.', None))

        waiting_p.add_transition(Transition(waiting_r, lambda x: x.startswith('p '), self._router_policy))
        waiting_p.add_transition(Transition(waiting_r, ignorable_line, None))
        waiting_p.add_transition(Transition(waiting_s, lambda x: x.startswith('r '), self._router_begin))  # "p" lines are optional
        waiting_p.add_transition(Transition(waiting_r, lambda x: x[:2] != 'p ', die('Expected "p " while parsing routers not "%s"')))
        waiting_p.add_transition(Transition(waiting_r, lambda x: x.strip() == '.', None))

        self._machine = FSM([waiting_r, waiting_s, waiting_w, waiting_p])
        self._relay_attrs = None

    def feed_line(self, line):
        """
        A line has been received.
        """
        self._machine.process(line)

    def done(self, *args):
        """
        All lines have been fed.
        """
        self._maybe_callback_router()

    def _maybe_callback_router(self):
        if self._relay_attrs is not None:
            self._create_relay(**self._relay_attrs)
            self._relay_attrs = None

    def _router_begin(self, data):
        self._maybe_callback_router()
        args = data.split()[1:]
        self._relay_attrs = dict(
            nickname=args[0],
            idhash=args[1],
            orhash=args[2],
            modified=args[3] + ' ' + args[4],
            ip=args[5],
            orport=args[6],
            dirport=args[7],
        )

    def _router_flags(self, data):
        args = data.split()[1:]
        self._relay_attrs['flags'] = args

    def _router_address(self, data):
        """only for IPv6 addresses"""
        args = data.split()[1:]
        try:
            self._relay_attrs['ip_v6'].extend(args)
        except KeyError:
            self._relay_attrs['ip_v6'] = list(args)

    def _router_bandwidth(self, data):
        args = data.split()[1:]
        kw = find_keywords(args)
        self._relay_attrs['bandwidth'] = kw['Bandwidth']

    def _router_policy(self, data):
        pass


class _AutomatMicrodescriptorParser(object):
    """
    Parsers microdescriptors line by line. New relays are emitted via
    the 'create_relay' callback.
    """
    _machine = automat.MethodicalMachine()

    def __init__(self, create_relay):
        self._create_relay = create_relay
        self._relay_attrs = None

    @_machine.input()
    def done(self, *args):
        """
        All lines have been fed.
        """

    @_machine.input()
    def _r_line(self, *args):
        pass

    @_machine.input()
    def _s_line(self, *args):
        pass

    @_machine.input()
    def _w_line(self, *args):
        pass

    @_machine.input()
    def _p_line(self, *args):
        pass

    @_machine.input()
    def _a_line(self, *args):
        pass

    @_machine.output()
    def create_relay(self, *args):
        r = self._create_relay(**self._relay_attrs)
        self._relay_attrs = None
        return r

    @_machine.output()
    def start_relay(self, *args):
        self._relay_attrs = dict()

    @_machine.output()
    def _parse_r(self, *args):
        assert len(args) >= 8
        self._relay_attrs.update(dict(
            nickname=args[0],
            idhash=args[1],
            orhash=args[2],
            modified=args[3] + ' ' + args[4],
            ip=args[5],
            orport=args[6],
            dirport=args[7],
        ))

    @_machine.output()
    def _parse_s(self, *args):
        self._relay_attrs['flags'] = args

    @_machine.output()
    def _parse_w(self, *args):
        # should only contain "bandwidth" ...
        kw = find_keywords(args)
        assert 'Bandwidth' in kw
        self._relay_attrs['bandwidth'] = kw['Bandwidth']

    @_machine.output()
    def _parse_a(self, *args):
        try:
            self._relay_attrs['ip_v6'].extend(args)
        except KeyError:
            self._relay_attrs['ip_v6'] = list(args)

    @_machine.output()
    def _error(self, *args):
        raise RuntimeError("Illegal state in microdescriptor parser")

    @_machine.state(initial=True)
    def waiting_r(self):
        """
        waiting for an 'r' line
        """

    @_machine.state()
    def waiting_s(self):
        """
        waiting for an 's' line
        """

    @_machine.state()
    def waiting_w(self):
        """
        waiting for an 's' line
        """

    @_machine.state()
    def error(self):
        """
        something bad happened
        """

    def feed_line(self, data):
        if not data:
            return
        args = data.split()
        try:
            {
                'r': self._r_line,
                's': self._s_line,
                'w': self._w_line,
                'p': self._p_line,
                'a': self._a_line,
                'OK': lambda: None,  # ignore
                'ns/all=': lambda: None,  # ignore
                '.': lambda: None,  # ignore
            }[args[0]](*args[1:])
        except KeyError:
            raise Exception(
                'Unknown microdescriptor line: "{}"'.format(args[0])
            )

    waiting_r.upon(
        _r_line,
        enter=waiting_s,
        outputs=[start_relay, _parse_r],
    )
    waiting_r.upon(
        _p_line,
        enter=waiting_r,
        outputs=[],
    )
    waiting_r.upon(
        done,
        enter=waiting_r,
        outputs=[],
    )

    waiting_s.upon(
        _r_line,
        enter=error,
        outputs=[_error],
    )
#    waiting_s.upon(
#        _r_line,
#        enter=waiting_s,
#        outputs=[create_relay, start_relay, _parse_r],
#    )
    waiting_s.upon(
        _s_line,
        enter=waiting_w,
        outputs=[_parse_s],
    )
    waiting_s.upon(
        _a_line,
        enter=waiting_s,
        outputs=[_parse_a],
    )
    waiting_s.upon(
        done,
        enter=waiting_r,
        outputs=[create_relay],
    )

    waiting_w.upon(
        _w_line,
        enter=waiting_r,
        outputs=[_parse_w, create_relay],
    )
    waiting_w.upon(
        _r_line,
        enter=waiting_s,
        outputs=[create_relay, start_relay, _parse_r],
    )
    waiting_w.upon(
        _a_line,
        enter=waiting_w,
        outputs=[_parse_a],
    )
    waiting_w.upon(
        done,
        enter=waiting_r,
        outputs=[create_relay],
    )
