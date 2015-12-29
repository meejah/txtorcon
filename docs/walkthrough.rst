Walkthrough
===========

.. _Twisted: https://twistedmatrix.com/documents/current/
.. _virtualenv: http://www.virtualenv.org/en/latest/

If this is your first time using a Tor controller library, you're in
the right spot. I presume at least some `familiarity <http://krondo.com/?page_id=1327>`_
with Twisted_ and asynchronous programming.


What We'll Learn
----------------
.. _NEWNYM: https://gitweb.torproject.org/torspec.git/tree/control-spec.txt#n379
.. _walkthrough directory: https://github.com/meejah/txtorcon/tree/master/walkthrough

In this tutorial, I will go through several examples building up a
small program. We will:

 * connect to a running Tor;
 * launch our own Tor;
 * change the configuration;
 * get some information from Tor;
 * listen for events;
 * and send a NEWNYM_ signal.

All the code examples are also in the `walkthrough directory`_.

Install txtorcon in a virtualenv
--------------------------------

First we need to be able to ``import txtorcon`` in a Python shell. We
will accomplish that in a virtualenv_.

.. note:: If you're using Debian or Ubuntu, ``pip install python-txtorcon`` may just work.

To try the latest released version of txtorcon in a virtualenv_ is
similar to other Python packages::

   virtualenv /tmp/txtorcon-venv
   /tmp/txtorcon-venv/bin/pip install txtorcon
   source /tmp/txtorcon-venv/bin/activate

You should now be able to run "import txtorcon" in a python shell, for
example::

   python -c "import txtorcon"

The above should produce no output. If you got an exception, or
something else went wrong, read up on virtualenv or ask "meejah" in
#tor-dev for help.


Connect to a Running Tor
------------------------

If you've got a system-wide Tor running, it defaults to port 9051 if
you have the control interface turned on. ``/etc/tor/torrc`` should
contain lines similar to this::

   ControlPort 9051
   CookieAuthentication 1

Alternatively, if you're currently running the Tor Browser Bundle, it
defaults to a port of 9151 and doesn't turn on cookie
authentication. Change the options to turn on cookie authentication
and change "9051" to "9151" in the following examples.


We will use the :meth:`txtorcon.build_tor_connection` API call, which
returns a Deferred that callbacks with a :class:`TorControlProtocol
<txtorcon.TorControlProtocol>` or :class:`TorState
<txtorcon.TorState>` instance (depending on whether the
``build_state`` kwarg was True -- the default -- or False).

The TorState instance takes a second or two to get built as it queries
Tor for all the current relays and creates a :class:`Router <txtorcon.Router>` instance of
which there are currently about 5000. TorControlProtocol alone is much
faster (dozens of milliseconds).

The code to do this would look something like:

.. sourcecode:: python

    from __future__ import print_function
    from twisted.internet.task import react
    from twisted.internet.defer import inlineCallbacks
    from twisted.internet.endpoints import TCP4ClientEndpoint
    import txtorcon

    @inlineCallbacks
    def main(reactor):
        # change the port to 9151 for Tor Browser Bundle
        connection = TCP4ClientEndpoint(reactor, "localhost", 9051)

        state = yield txtorcon.build_tor_connection(connection)
        print("Connected to tor {state.protocol.version}".format(state=state))
        print("Current circuits:")
        for circ in state.circuits.values():
            path = '->'.join([r.name for r in circ.path])
            print("  {circ.id}: {circ.state}, {path}".format(circ=circ, path=path))

        # can also do "low level" things with the protocol
        proto = state.protocol
        answer = yield proto.queue_command("GETINFO version")
        print("GETINFO version: {answer}".format(answer=answer))

    react(main)

If all is well, you should see some output like this::

    python walkthrough/0_connection.py
    Connected to tor 0.2.5.12 (git-3731dd5c3071dcba)
    Current circuits:
      16929: BUILT, someguard->ecrehd->aTomicRelayFR1
      16930: BUILT, someguard->Ferguson->NLNode1EddaiSu
    GETINFO version: version=0.2.5.12 (git-3731dd5c3071dcba)


Launch Our Own Tor
------------------

.. _GETINFO: https://gitweb.torproject.org/torspec.git/blob/HEAD:/control-spec.txt#l444
.. _mkdtemp: https://docs.python.org/2/library/tempfile.html?highlight=mkdtem#tempfile.mkdtemp

For some use-cases you will want to launch a private Tor
instance. txtorcon provides :meth:`txtorcon.launch_tor` to do just that. This also
uses some Tor commands to link the controller to the Tor instance, so
that if the connection is lost Tor will shut itself down.

The main difference between connecting and launching is that you have
to provide a configuration to launch Tor with. This is provided via a
:class:`TorConfig<txtorcon.TorConfig>` instance. This class is a
little "magic" in order to provide a nice API, and so you simply set
configuration options as members. A minimal configuration to launch a
Tor might be::

   config = txtorcon.TorConfig()
   config.ORPort = 0
   config.SocksPort = 9999

The ``launch_tor`` method itself also adds several necessary
configuration options but *only if* they aren't supplied already. For
example, if you want to maintain state (or hidden service keys)
between launches, provide your own ``DataDirectory``. The configuration
keys ``launch_tor`` adds are:

 * ``DataDirectory`` a mkdtemp_ directory in ``/tmp/`` (which is deleted at
   exit, unless it was user-specified)
 * ``ControlPort`` is set to 9052 unless already specified
 * ``CookieAuthentication`` is set to 1
 * ``__OwningControllerProcess`` is set to our PID

Check out the :meth:`txtorcon.launch_tor` documentation. You'll likely want
to provide a ``progress_updates`` listener to provide interesting
information to your user. Here's a full example::

    #!/usr/bin/env python

    from __future__ import print_function
    import os
    from twisted.internet.defer import inlineCallbacks
    from twisted.internet.task import react
    from twisted.internet.endpoints import TCP4ClientEndpoint
    import txtorcon

    def progress(percent, tag, summary):
        """
        Progress update from tor; we print a cheezy progress bar and the
        message.
        """
        ticks = int((percent/100.0) * 10.0)
        prog = (ticks * '#') + ((10 - ticks) * '.')
        print('{} {}'.format(prog, summary))

    @inlineCallbacks
    def main(reactor):
        config = txtorcon.TorConfig()
        config.ORPort = 0
        config.SocksPort = 9998
        try:
            os.mkdir('tor-data')
        except OSError:
            pass
        config.DataDirectory = './tor-data'

        try:
            process = yield txtorcon.launch_tor(
                config, reactor, progress_updates=progress
            )
        except Exception as e:
            print("Error launching tor:", e)
            return

        protocol = process.tor_protocol
        print("Tor has launched.")
        print("Protocol:", protocol)
        info = yield protocol.get_info('traffic/read', 'traffic/written')
        print(info)

        # explicitly stop tor by either disconnecting our protocol or the
        # Twisted IProcessProtocol (or just exit our program)
        print("Killing our tor, PID={pid}".format(pid=process.transport.pid))
        yield process.transport.signalProcess('TERM')

    react(main)

If you've never seen the ``inlineCallbacks`` decorator, then you
should `read up on it
<https://twistedmatrix.com/documents/current/api/twisted.internet.defer.html#inlineCallbacks>`_.
Once we get the Tor instance launched, we just make two GETINFO_ calls
and then explicitly kill it. You can also simply exit, which will
cause the underlying Tor to also exit.


Putting It All Together
-----------------------

So, now we've gotten a basic connection to Tor (either by launching
one or connecting to a running one) and basically done nothing but
exit.

Let's do something slightly more interesting. We will connect to a
running Tor (like the first example), issue the NEWNYM_ signal (which
tells Tor to no longer use any existing circuits for new connections)
and then continuously monitor two events: circuit events via
``TorState`` interfaces and ``INFO`` messages via a raw
``add_event_listener``.

First, we add a simple implementation of :class:`txtorcon.ICircuitListener`::

    @implementer(txtorcon.ICircuitListener)
    class MyCircuitListener(object):

        def circuit_new(self, circuit):
            print("\n\nnew", circuit)

        def circuit_launched(self, circuit):
            print("\n\nlaunched", circuit)

        def circuit_extend(self, circuit, router):
            print("\n\nextend", circuit)

        def circuit_built(self, circuit):
            print("\n\nbuilt", circuit)

        def circuit_closed(self, circuit, **kw):
            print("\n\nclosed", circuit, kw)

        def circuit_failed(self, circuit, **kw):
            print("\n\nfailed", circuit, kw)

Next, to illustrate setting up TorState from a TorControlProtocol
directly we first make a "bare" protocol connection, and then use a
TorState classmethod (with the protocol instance) to query Tor's state
(this instance also adds listeners to stay updated).

Then we use ``TorControlProtocol.signal`` to send a NEWNYM_
request. After that we create a ``TorState`` instance, print out all
existing circuits and set up listeners for circuit events (an instance
of ``MyCircuitListener``) and INFO messages (via our own method).

Note there is a :class:`txtorcon.CircuitListenerMixin`_ class -- and
similar interfaces for :class:`txtorcon.Stream`_ as well -- which
makes it easier to write a listener subclass.

Here is the full listing::

    from __future__ import print_function
    from twisted.internet.task import react
    from twisted.internet.defer import inlineCallbacks, Deferred
    from twisted.internet.endpoints import TCP4ClientEndpoint
    from zope.interface import implementer
    import txtorcon


    @implementer(txtorcon.ICircuitListener)
    class MyCircuitListener(object):

        def circuit_new(self, circuit):
            print("new", circuit)

        def circuit_launched(self, circuit):
            print("launched", circuit)

        def circuit_extend(self, circuit, router):
            print("extend", circuit)

        def circuit_built(self, circuit):
            print("built", circuit)

        def circuit_closed(self, circuit, **kw):
            print("closed", circuit, kw)

        def circuit_failed(self, circuit, **kw):
            print("failed", circuit, kw)


    @inlineCallbacks
    def main(reactor):
        # change the port to 9151 for Tor Browser Bundle
        tor_ep = TCP4ClientEndpoint(reactor, "localhost", 9051)
        connection = yield txtorcon.build_tor_connection(tor_ep, build_state=False)
        version = yield connection.get_info('version', 'events/names')
        print("Connected to Tor {version}".format(**version))
        print("Events:", version['events/names'])

        print("Building state.")
        state = yield txtorcon.TorState.from_protocol(connection)

        print("listening for circuit events")
        state.add_circuit_listener(MyCircuitListener())

        print("Issuing NEWNYM.")
        yield connection.signal('NEWNYM')
        print("OK.")

        print("Existing circuits:")
        for c in state.circuits.values():
            print(' ', c)

        print("listening for INFO events")
        def print_info(i):
            print("INFO:", i)
        connection.add_event_listener('INFO', print_info)

        done = Deferred()
        yield done  # never callback()s so infinite loop

    react(main)

If your Tor instance has been dormant for a while, try something like
``torsocks curl https://www.torprojec.org`` in another termainl so you
can see some more logging and circuit events.
