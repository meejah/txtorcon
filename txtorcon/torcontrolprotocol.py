from __future__ import with_statement

from twisted.python import log
from twisted.internet import defer
from twisted.internet.interfaces import IProtocolFactory
from twisted.protocols.basic import LineOnlyReceiver
from zope.interface import implements

from txtorcon.util import hmac_sha256, compare_via_hash
from txtorcon.log import txtorlog

from txtorcon.interface import ITorControlProtocol
from spaghetti import FSM, State, Transition

import os
import re
import types
import base64

DEFAULT_VALUE = 'DEFAULT'
DEBUG = False


class TorProtocolError(RuntimeError):
    """
    Happens on 500-level responses in the protocol, almost certainly
    in an errback chain.

    :ivar code: the actual error code
    :ivar text: other text from the protocol
    """

    def __init__(self, code, text):
        self.code = code
        self.text = text
        super(TorProtocolError, self).__init__(text)

    def __str__(self):
        return str(self.code) + ' ' + self.text


class TorProtocolFactory(object):
    """
    Builds TorControlProtocol objects. Implements IProtocolFactory for
    Twisted interaction.

    If your running Tor doesn't support COOKIE authentication, then
    you should supply a password. FIXME: should supply a
    password-getting method, instead.
    """

    implements(IProtocolFactory)

    def __init__(self, password=None):
        """
        Builds protocols to talk to a Tor client on the specified
        address. For example::

        TCP4ClientEndpoint(reactor, "localhost", 9051).connect(TorProtocolFactory())
        reactor.run()

        By default, COOKIE authentication is used if
        available. Otherwise, a password should be supplied. FIXME:
        user should supply a password getter, not a password (e.g. if
        they want to prompt)
        """
        self.password = password

    def doStart(self):
        ":api:`twisted.internet.interfaces.IProtocolFactory` API"

    def doStop(self):
        ":api:`twisted.internet.interfaces.IProtocolFactory` API"

    def buildProtocol(self, addr):
        ":api:`twisted.internet.interfaces.IProtocolFactory` API"
        proto = TorControlProtocol(self.password)
        proto.factory = self
        return proto


class Event(object):
    """
    A class representing one of the valid EVENTs that Tor
    supports.

    This allows you to listen for such an event; see
    TorController.add_event The callbacks will be called every time
    the event in question is received.
    """
    def __init__(self, name):
        self.name = name
        self.callbacks = []

    def listen(self, cb):
        self.callbacks.append(cb)

    def unlisten(self, cb):
        self.callbacks.remove(cb)

    def got_update(self, data):
        #print self.name,"got_update:",data
        for cb in self.callbacks:
            cb(data)


def unquote(word):
    if len(word) == 0:
        return word
    if word[0] == '"' and word[-1] == '"':
        return word[1:-1]
    elif word[0] == "'" and word[-1] == "'":
        return word[1:-1]
    return word


def parse_keywords(lines, multiline_values=True):
    """
    Utility method to parse name=value pairs (GETINFO etc). Takes a
    string with newline-separated lines and expects at most one = sign
    per line. Accumulates multi-line values.

    :param multiline_values:
        The default is True which allows for multi-line values until a
        line with the next = sign on it. So: '''Foo=bar\nBar'''
        produces one key, 'Foo', with value 'bar\nBar' -- set to
        False, there would be two keys: 'Foo' with value 'bar' and
        'Bar' with value DEFAULT_VALUE.
    """

    rtn = {}
    key = None
    value = ''
    ## FIXME could use some refactoring to reduce code duplication!
    for line in lines.split('\n'):
        if line.strip() == 'OK':
            continue

        if '=' in line:
            if key:
                if key in rtn:
                    if isinstance(rtn[key], types.ListType):
                        rtn[key].append(unquote(value))
                    else:
                        rtn[key] = [rtn[key], unquote(value)]
                else:
                    rtn[key] = unquote(value)
            (key, value) = line.split('=', 1)

        else:
            if key is None:
                rtn[line.strip()] = DEFAULT_VALUE

            elif multiline_values is False:
                rtn[key] = value
                rtn[line.strip()] = DEFAULT_VALUE
                key = None
                value = ''

            else:
                value = value + '\n' + line
    if key:
        if key in rtn:
            if isinstance(rtn[key], types.ListType):
                rtn[key].append(unquote(value))
            else:
                rtn[key] = [rtn[key], unquote(value)]
        else:
            rtn[key] = unquote(value)
    return rtn


class TorControlProtocol(LineOnlyReceiver):
    """
    This is the main class that talks to a Tor and implements the "raw"
    procotol.

    This instance does not track state; see :class:`txtorcon.TorState`
    for the current state of all Circuits, Streams and Routers.

    :meth:`txtorcon.TorState.build_circuit` allows you to build custom
    circuits.

    :meth:`txtorcon.TorControlProtocol.add_event_listener` can be used
    to listen for specific events.

    To see how circuit and stream listeners are used, see
    :class:`txtorcon.TorState`, which is also the place to go if you
    wish to add your own stream or circuit listeners.
    """

    implements(ITorControlProtocol)

    def __init__(self, password=None):
        """
        password is only used if the Tor doesn't have COOKIE
        authentication turned on. Tor's default is COOKIE.
        """

        self.password = password
        """If set, a password to use for authentication to Tor
        (default is to use COOKIE, however)."""

        self.version = None
        """Version of Tor we've connected to."""

        self.is_owned = None
        """If not None, this is the PID of the Tor process we own
        (TAKEOWNERSHIP, etc)."""

        self.events = {}
        """events we've subscribed to (keyed by name like "GUARD", "STREAM")"""

        self.valid_events = {}
        """all valid events (name -> Event instance)"""

        self.valid_signals = []
        """A list of all valid signals we accept from Tor"""

        self.post_bootstrap = defer.Deferred()
        """
        This Deferred is triggered when we're done setting up
        (authentication, getting information from Tor). You will want
        to use this to do things with the :class:`TorControlProtocol`
        class when it's set up, like::

            def setup_complete(proto):
                print "Setup complete, attached to Tor version",proto.version

            def setup(proto):
                proto.post_bootstrap.addCallback(setup_complete)

            TCP4ClientEndpoint(reactor, "localhost", 9051).connect(TorProtocolFactory())
            d.addCallback(setup)

        See the helper method :func:`txtorcon.build_tor_connection`.
        """

        ## variables related to the state machine
        self.defer = None               # Deferred we returned for the current command
        self.response = ''
        self.code = None
        self.command = None             # currently processing this command
        self.commands = []              # queued commands

        ## Here we build up the state machine. Mostly it's pretty
        ## simply, confounded by the fact that 600's (notify) can come
        ## at any time AND can be multi-line itself. Luckily, these
        ## can't be nested, nor can the responses be interleaved.

        idle = State("IDLE")
        recv = State("RECV")
        recvmulti = State("RECV_PLUS")
        recvnotify = State("NOTIFY_MULTILINE")

        idle.add_transition(Transition(idle,
                                       self._is_single_line_response,
                                       self._broadcast_response))
        idle.add_transition(Transition(recvmulti,
                                       self._is_multi_line,
                                       self._start_command))
        idle.add_transition(Transition(recv,
                                       self._is_continuation_line,
                                       self._start_command))

        recv.add_transition(Transition(recv,
                                       self._is_continuation_line,
                                       self._accumulate_response))
        recv.add_transition(Transition(idle,
                                       self._is_finish_line,
                                       self._broadcast_response))

        recvmulti.add_transition(Transition(recv,
                                            self._is_end_line,
                                            lambda x: None))
        recvmulti.add_transition(Transition(recvmulti,
                                            self._is_not_end_line,
                                            self._accumulate_multi_response))

        self.fsm = FSM([recvnotify, idle, recvmulti, recv])
        self.state_idle = idle
        ## hand-set initial state default start state is first in the
        ## list; the above looks nice in dotty though
        self.fsm.state = idle
        if DEBUG:
            self.debuglog = open('txtorcon-debug.log', 'w')
            with open('fsm.dot', 'w') as fsmfile:
                fsmfile.write(self.fsm.dotty())

    ## see end of file for all the state machine matcher and
    ## transition methods.

    def get_info_raw(self, *args):
        """
        Mostly for internal use; gives you the raw string back from
        the GETINFO command. See :meth:`getinfo <txtorcon.TorControlProtocol.get_info>`
        """
        info = ' '.join(map(lambda x: str(x), list(args)))
        return self.queue_command('GETINFO %s' % info)

    def get_info_incremental(self, key, line_cb):
        """
        Mostly for internal use; calls GETINFO for a single key and
        calls line_cb with each line received, as it is received.

        See :meth:`getinfo <txtorcon.TorControlProtocol.get_info>`
        """

        return self.queue_command('GETINFO %s' % key, line_cb)

    ## The following methods are the main TorController API and
    ## probably the most interesting for users.

    def get_info(self, *args):
        """
        Uses GETINFO to obtain informatoin from Tor.

        :param args:
            should be a list or tuple of strings which are valid
            information keys. For valid keys, see control-spec.txt
            from torspec.

            .. todo:: make some way to automagically obtain valid
                keys, either from running Tor or parsing control-spec

        :return:
            a ``Deferred`` which will callback with a dict containing
            the keys you asked for. This just inserts ``parse_keywords``
            in the callback chain; if you want to avoid the parsing
            into a dict, you can use get_info_raw instead.
        """
        return self.get_info_raw(*args).addCallback(parse_keywords).addErrback(log.err)

    def get_conf(self, *args):
        """
        Uses GETCONF to obtain configuration values from Tor.

        :param args: any number of strings which are keys to get. To
            get all valid configuraiton names, you can call:
            ``get_info('config/names')``

        :return: a Deferred which callbacks with one or many
            configuration values (depends on what you asked for). See
            control-spec for valid keys (you can also use TorConfig which
            will come set up with all the keys that are valid). The value
            will be a dict.

        Note that Tor differentiates between an empty value and a
        default value; in the raw protocol one looks like '250
        MyFamily' versus '250 MyFamily=' where the latter is set to
        the empty string and the former is a default value. We
        differentiate these by setting the value in the dict to
        DEFAULT_VALUE for the default value case, or an empty string
        otherwise.
        """

        return self.queue_command('GETCONF %s' % ' '.join(args)).addCallback(parse_keywords).addErrback(log.err)

    def get_conf_raw(self, *args):
        """
        Same as get_conf, except that the results are not parsed into a dict
        """

        return self.queue_command('GETCONF %s' % ' '.join(args))

    def set_conf(self, *args):
        """
        set configuration values. see control-spec for valid
        keys. args is treated as a list containing name then value
        pairs. For example, ``set_conf('foo', 'bar')`` will (attempt
        to) set the key 'foo' to value 'bar'.

        :return: a ``Deferred`` that will callback with the response
            ('OK') or errback with the error code and message (e.g.
            ``"552 Unrecognized option: Unknown option 'foo'.  Failing."``)
        """
        if len(args) % 2:
            d = defer.Deferred()
            d.errback(RuntimeError("Expected an even number of arguments."))
            return d
        strargs = map(lambda x: str(x), args)
        keys = [strargs[i] for i in range(0, len(strargs), 2)]
        values = [strargs[i] for i in range(1, len(strargs), 2)]

        def maybe_quote(s):
            if ' ' in s:
                return '"%s"' % s
            return s
        values = map(maybe_quote, values)
        args = ' '.join(map(lambda x, y: '%s=%s' % (x, y), keys, values))
        return self.queue_command('SETCONF ' + args)

    def signal(self, nm):
        """
        Issues a signal to Tor. See control-spec or
        :attr:`txtorcon.TorControlProtocol.valid_signals` for which ones
        are available and their return values.

        :return: a ``Deferred`` which callbacks with Tor's response
            (``OK`` or something like ``552 Unrecognized signal code "foo"``).
        """
        if not nm in self.valid_signals:
            raise RuntimeError("Invalid signal " + nm)
        return self.queue_command('SIGNAL %s' % nm)

    def add_event_listener(self, evt, callback):
        """
        :param evt: event name, see also
        :var:`txtorcon.TorControlProtocol.events` .keys()

        Add a listener to an Event object. This may be called multiple
        times for the same event. If it's the first listener, a new
        SETEVENTS call will be initiated to Tor.

        Currently the callback is any callable that takes a single
        argument, that is the text collected for the event from the
        tor control protocol.

        :Return: ``None``

        .. todo:: need an interface for the callback
        """

        if not evt in self.valid_events.values():
            try:
                evt = self.valid_events[evt]
            except:
                raise RuntimeError("Unknown event type: " + evt)

        if evt.name not in self.events:
            self.events[evt.name] = evt
            self.queue_command('SETEVENTS %s' % ' '.join(self.events.keys()))
        evt.listen(callback)
        return None

    def remove_event_listener(self, evt, cb):
        if not evt in self.valid_events.values():
            try:
                evt = self.valid_events[evt]
            except:
                raise RuntimeError("Unknown event type: " + evt)

        evt.unlisten(cb)
        if len(evt.callbacks) == 0:
            del self.events[evt.name]
            self.queue_command('SETEVENTS %s' % ' '.join(self.events.keys()))

    def protocolinfo(self):
        """
        :return: a Deferred which will give you PROTOCOLINFO; see control-spec
        """

        return self.queue_command("PROTOCOLINFO 1")

    def authenticate(self, passphrase):
        """Call the AUTHENTICATE command."""
        return self.queue_command('AUTHENTICATE ' + passphrase.encode("hex"))

    def quit(self):
        return self.queue_command('QUIT')

    def queue_command(self, cmd, arg=None):
        """
        returns a Deferred which will fire with the response data when
        we get it
        """

        d = defer.Deferred()
        self.commands.append((d, cmd, arg))
        self._maybe_issue_command()
        return d

    ## the remaining methods are internal API implementations,
    ## callbacks and state-tracking methods -- you shouldn't have any
    ## need to call them.

    def lineReceived(self, line):
        """
        :api:`twisted.protocols.basic.LineOnlyReceiver` API
        """

        if DEBUG:
            self.debuglog.write(line + '\n')
            self.debuglog.flush()

        self.fsm.process(line)

    def connectionMade(self):
        "LineOnlyReceiver API (or parent?)"
        txtorlog.msg('got connection, authenticating')
        self.protocolinfo().addCallback(self._do_authenticate).addErrback(self._auth_failed)

    def _handle_notify(self, code, rest):
        """
        Internal method to deal with 600-level responses.
        """

        firstline = rest[:rest.find('\n')]
        args = firstline.split()
        if args[0] in self.events:
            self.events[args[0]].got_update(rest[len(args[0]) + 1:])
            return

        raise RuntimeError("Wasn't listening for event of type " + args[0])

    def _maybe_issue_command(self):
        """
        If there's at least one command queued and we're not currently
        processing a command, this will issue the next one on the
        wire.
        """
        if self.command:
            return

        if len(self.commands):
            self.command = self.commands.pop(0)
            (d, cmd, cmd_arg) = self.command
            self.defer = d

            if DEBUG:
                #print "NOTIFY",code,rest
                self.debuglog.write(cmd + '\n')
                self.debuglog.flush()

            self.transport.write(cmd + '\r\n')

    def _auth_failed(self, fail):
        """
        Errback if authentication fails.
        """

        if self.post_bootstrap:
            self.post_bootstrap.errback(fail)
            return None
        return fail

    def _safecookie_authchallenge(self, reply):
        """
        Callback on AUTHCHALLENGE SAFECOOKIE
        """

        kw = parse_keywords(reply.replace(' ', '\n'))

        server_hash = base64.b16decode(kw['SERVERHASH'])
        server_nonce = base64.b16decode(kw['SERVERNONCE'])
        ## FIXME put string in global. or something.
        expected_server_hash = hmac_sha256("Tor safe cookie authentication server-to-controller hash",
                                           self.cookie_data + self.client_nonce + server_nonce)

        if not compare_via_hash(expected_server_hash, server_hash):
            raise RuntimeError('Server hash not expected; wanted "%s" and got "%s".' % (base64.b16encode(expected_server_hash),
                                                                                        base64.b16encode(server_hash)))

        client_hash = hmac_sha256("Tor safe cookie authentication controller-to-server hash",
                                  self.cookie_data + self.client_nonce + server_nonce)
        client_hash_hex = base64.b16encode(client_hash)
        return self.queue_command('AUTHENTICATE %s' % client_hash_hex)

    def _do_authenticate(self, protoinfo):
        """
        Callback on PROTOCOLINFO to actually authenticate once we know
        what's supported.
        """

        methods = None
        for line in protoinfo.split('\n'):
            if line[:5] == 'AUTH ':
                kw = parse_keywords(line[5:].replace(' ', '\n'))
                methods = kw['METHODS'].split(',')
        if not methods:
            raise RuntimeError("Didn't find AUTH line in PROTOCOLINFO response.")

        if 'SAFECOOKIE' in methods:
            cookie = re.search('COOKIEFILE="(.*)"', protoinfo).group(1)
            self.cookie_data = open(cookie, 'r').read()
            if len(self.cookie_data) != 32:
                raise RuntimeError("Expected authentication cookie to be 32 bytes, got %d" % len(self.cookie_data))
            txtorlog.msg("Using SAFECOOKIE authentication", cookie,
                         len(self.cookie_data), "bytes")
            self.client_nonce = os.urandom(32)

            d = self.queue_command('AUTHCHALLENGE SAFECOOKIE %s' % base64.b16encode(self.client_nonce))
            d.addCallback(self._safecookie_authchallenge).addCallback(self._bootstrap).addErrback(self._auth_failed)
            return

        elif 'COOKIE' in methods:
            cookie = re.search('COOKIEFILE="(.*)"', protoinfo).group(1)
            with open(cookie, 'r') as cookiefile:
                data = cookiefile.read()
            if len(data) != 32:
                raise RuntimeError("Expected authentication cookie to be 32 bytes, got %d" % len(data))
            txtorlog.msg("Using COOKIE authentication", cookie, len(data), "bytes")
            self.authenticate(data).addCallback(self._bootstrap).addErrback(self._auth_failed)
            return

        if self.password:
            self.authenticate(self.password).addCallback(self._bootstrap).addErrback(self._auth_failed)
            return

        raise RuntimeError("The Tor I connected to doesn't support SAFECOOKIE nor COOKIE authentication and I have no password.")

    def _set_valid_events(self, events):
        "used as a callback; see _bootstrap"
        self.valid_events = {}
        for x in events.split():
            self.valid_events[x] = Event(x)

    @defer.inlineCallbacks
    def _bootstrap(self, *args):
        """
        The inlineCallbacks decorator allows us to make this method
        look synchronous; see the Twisted docs. Each yeild is for a
        Deferred after which the method continues. When this method
        finally exits, we're set up and do the post_bootstrap
        callback.
        """

        ## unfortunately I don't see a way to get this from the runing
        ## tor like the events...so this was taken from some version
        ## of the control-spec and must be kept up-to-date (or accpet
        ## any signal name and just wait for the reply?
        self.valid_signals = ["RELOAD", "DUMP", "DEBUG", "NEWNYM", "CLEARDNSCACHE"]

        self.version = yield self.get_info('version')
        self.version = self.version['version']
        txtorlog.msg("Connected to a Tor with VERSION", self.version)
        eventnames = yield self.get_info('events/names')
        eventnames = eventnames['events/names']
        self._set_valid_events(eventnames)

        yield self.queue_command('USEFEATURE EXTENDED_EVENTS')

        self.post_bootstrap.callback(self)
        self.post_bootstrap = None
        defer.returnValue(self)

    ##
    ## State Machine transitions and matchers. See the __init__ method
    ## for a way to output a GraphViz dot diagram of the machine.
    ##

    def _is_end_line(self, line):
        "for FSM"
        return line.strip() == '.'

    def _is_not_end_line(self, line):
        "for FSM"
        return not self._is_end_line(line)

    def _is_single_line_response(self, line):
        "for FSM"
        try:
            code = int(line[:3])
        except:
            return False

        sl = len(line) > 3 and line[3] == ' '
        #print "single line?",line,sl
        if sl:
            self.code = code
            return True
        return False

    def _start_command(self, line):
        "for FSM"
        # print "startCommand",self.code,line
        self.code = int(line[:3])
        # print "startCommand:",self.code
        if self.command and self.command[2] is not None:
            self.command[2](line[4:])
        else:
            self.response = line[4:] + '\n'
        return None

    def _is_continuation_line(self, line):
        "for FSM"
        # print "isContinuationLine",self.code,line
        code = int(line[:3])
        if self.code and self.code != code:
            raise RuntimeError("Unexpected code %d, wanted %d" % (code,
                                                                  self.code))
        return line[3] == '-'

    def _is_multi_line(self, line):
        "for FSM"
        # print "isMultiLine",self.code,line,line[3] == '+'
        code = int(line[:3])
        if self.code and self.code != code:
            raise RuntimeError("Unexpected code %d, wanted %d" % (code,
                                                                  self.code))
        return line[3] == '+'

    def _accumulate_multi_response(self, line):
        "for FSM"
        if self.command and self.command[2] is not None:
            self.command[2](line)

        else:
            self.response += (line + '\n')
        return None

    def _accumulate_response(self, line):
        "for FSM"
        if self.command and self.command[2] is not None:
            self.command[2](line[4:])

        else:
            self.response += (line[4:] + '\n')
        return None

    def _is_finish_line(self, line):
        "for FSM"
        # print "isFinish",line
        if len(line) < 1:
            return False
        if line[0] == '.':
            return True
        if len(line) > 3 and line[3] == ' ':
            return True
        return False

    def _broadcast_response(self, line):
        "for FSM"
        # print "BCAST",line
        if len(line) > 3:
            if self.code >= 200 and self.code < 300 and self.command and self.command[2] is not None:
                self.command[2](line[4:])
                resp = ''

            else:
                resp = self.response + line[4:]
        else:
            resp = self.response
        self.response = ''
        if self.code >= 200 and self.code < 300:
            if self.defer is None:
                raise RuntimeError("Got a response, but didn't issue a command.")
            self.defer.callback(resp)
        elif self.code >= 500 and self.code < 600:
            err = TorProtocolError(self.code, resp)
            self.defer.errback(err)
        elif self.code >= 600 and self.code < 700:
            self._handle_notify(self.code, resp)
            self.code = None
            return
        elif self.code is None:
            raise RuntimeError("No code set yet in broadcast response.")
        else:
            raise RuntimeError("Unknown code in broadcast response %d." % self.code)

        ## note: we don't do this for 600-level responses
        self.command = None
        self.code = None
        self.defer = None
        self._maybe_issue_command()
        return None
