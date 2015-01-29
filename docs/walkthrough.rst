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

.. note:: If you're using Debian or Ubuntu, ``pip install txtorcon`` may just work. 

For the virtualenv, first get the code::

   git clone https://github.com/meejah/txtorcon
   cd txtorcon

Now, we can use the Makefile there to create ourselves a virtualenv,
activate it and install all the pre-requisites::

   make venv
   . venv/bin/activate
   pip install -r requirements.txt
   pip install -r dev-requirements.txt  # optional

You should now be able to run "import txtorcon" in a python shell, for
example::

   python -c "import txtorcon"

The above should produce no output. If you got an exception, or
something else went wrong, read up on virtualenv or try a global
install with ``python setup.py install``

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

   from twisted.internet import reactor
   from twisted.internet.endpoints import TCP4ClientEndpoint
   import txtorcon

      def example(state):
	  """
	  This callback gets called after we've connected and loaded all the
	  current Tor state. state is a TorState instance.
	  """
	  print "Fully bootstrapped state:", state
	  print "   with bootstrapped protocol:", state.protocol
	  reactor.stop()

      ## change the port to 9151 for Tor Browser Bundle
      connection = TCP4ClientEndpoint(reactor, "localhost", 9051)

      d = txtorcon.build_tor_connection(connection)
      d.addCallback(example)

      ## this will only return after reactor.stop() is called
      reactor.run()

If all is well, you should see two lines get printed out and then the
script will exit::

   python 0_connection.py 
   Fully bootstrapped state: <txtorcon.torstate.TorState object at 0x21cf710>
      with bootstrapped protocol: <txtorcon.torcontrolprotocol.TorControlProtocol instance at 0x21c81b8>

Launch Our Own Tor
------------------

.. _GETINFO: https://gitweb.torproject.org/torspec.git/blob/HEAD:/control-spec.txt#l444
.. _mkdtemp: https://docs.python.org/2/library/tempfile.html?highlight=mkdtem#tempfile.mkdtemp

For some use-cases you will want to launch a private Tor
instance. txtorcon provides :meth:`txtorcon.launch_tor` to do just that. This also
uses some Tor commands to link the controller to the Tor instance, so
that if the connection is lost Tor will shut itself down.

The main difference between connecting and launching is that you have
to provide a configuration to launch a Tor with. This is provided via
a :class:`TorConfig<txtorcon.TorConfig>` instance. This class is a
little "magic" in order to provide a nice API, and so you simply set
configuration options as members. A minimal configuration to launch a Tor might
be::

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

   import os
   from twisted.internet import reactor, defer
   from twisted.internet.endpoints import TCP4ClientEndpoint
   import txtorcon

   @defer.inlineCallbacks
   def launched(process_proto):
       """
       This callback gets called after Tor considers itself fully
       bootstrapped -- it has created a circuit. We get the
       TorProcessProtocol object, which has the TorControlProtocol
       instance as .tor_protocol
       """

       protocol = process_proto.tor_protocol
       print "Tor has launched.\nProtocol:", protocol
       info = yield protocol.get_info('traffic/read', 'traffic/written')
       print info
       reactor.stop()

   def error(failure):
       print "There was an error", failure.getErrorMessage()
       reactor.stop()

   def progress(percent, tag, summary):
       ticks = int((percent/100.0) * 10.0)
       prog = (ticks * '#') + ((10 - ticks) * '.')
       print '%s %s' % (prog, summary)

   config = txtorcon.TorConfig()
   config.ORPort = 0
   config.SocksPort = 9999
   try:
       os.mkdir('tor-data')
   except OSError:
       pass
   config.DataDirectory = './tor-data'

   d = txtorcon.launch_tor(config, reactor, progress_updates=progress)
   d.addCallback(launched).addErrback(error)

   ## this will only return after reactor.stop() is called
   reactor.run()

If you've never seen the ``defer.inlineCallbacks`` decorator, then you
should `read up on it
<https://twistedmatrix.com/documents/current/api/twisted.internet.defer.html#inlineCallbacks>`_.
Once we get the Tor instance launched, we just make two GETINFO_ calls
and then exit (which will cause the underlying Tor to also exit).

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

   class MyCircuitListener(object):
       implements(txtorcon.ICircuitListener)
       def circuit_new(self, circuit):
	   print "new", circuit

       def circuit_launched(self, circuit):
	   print "launched", circuit

       def circuit_extend(self, circuit, router):
	   print "extend", circuit

       def circuit_built(self, circuit):
	   print "built", circuit

       def circuit_closed(self, circuit, **kw):
	   print "closed", circuit, kw

       def circuit_failed(self, circuit, **kw):
	   print "failed", circuit, kw

Next, to illustrate setting up TorState from a TorControlProtocol
directly, we add a ``main()`` method that uses ``inlineCallbacks`` to do a
few things sequentially after startup. First we use
``TorControlProtocol.signal`` to send a NEWNYM_ request. After that we
create a ``TorState`` instance, print out all existing circuits and set
up listeners for circuit events (an instance of ``MyCircuitListener``)
and INFO messages (via our own method).

Here is the full listing::

   from twisted.internet import reactor, defer
   from twisted.internet.endpoints import TCP4ClientEndpoint
   from zope.interface import implements
   import txtorcon

   ## change the port to 9151 for Tor Browser Bundle
   connection = TCP4ClientEndpoint(reactor, "localhost", 9051)

   def error(failure):
       print "Error:", failure.getErrorMessage()
       reactor.stop()

   class MyCircuitListener(object):
       implements(txtorcon.ICircuitListener)
       def circuit_new(self, circuit):
	   print "new", circuit

       def circuit_launched(self, circuit):
	   print "launched", circuit

       def circuit_extend(self, circuit, router):
	   print "extend", circuit

       def circuit_built(self, circuit):
	   print "built", circuit

       def circuit_closed(self, circuit, **kw):
	   print "closed", circuit, kw

       def circuit_failed(self, circuit, **kw):
	   print "failed", circuit, kw


   @defer.inlineCallbacks
   def main(connection):
       version = yield connection.get_info('version', 'events/names')
       print "Connected to Tor.", version['version']
       print version['events/names']

       print "Issuing NEWNYM."
       yield connection.signal('NEWNYM')
       print "OK."

       print "Building state."
       state = txtorcon.TorState(connection)
       yield state.post_bootstrap
       print "State initialized."
       print "Existing circuits:"
       for c in state.circuits.values():
	   print ' ', c

       print "listening for circuit events"
       state.add_circuit_listener(MyCircuitListener())

       print "listening for INFO events"
       def print_info(i):
	   print "INFO:", i
       connection.add_event_listener('INFO', print_info)

       ## since we don't call reactor.stop(), we keep running

   d = txtorcon.build_tor_connection(connection, build_state=False)
   d.addCallback(main).addErrback(error)

   ## this will only return after reactor.stop() is called
   reactor.run()

