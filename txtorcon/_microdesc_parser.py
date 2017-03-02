
from .util import find_keywords
import automat


class MicrodescriptorParser(object):
    """
    Parsers microdescriptors line by line. New relays are emitted via
    the 'create_relay' callback.
    """
    _machine = automat.MethodicalMachine()

    def __init__(self, create_relay):
        self._create_relay = create_relay
        self._relay_attrs = None

    @_machine.input()
    def line(self, line):
        """
        A line has been received.
        """

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
