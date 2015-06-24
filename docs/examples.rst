Examples
========

In the :file:`examples/` sub-directory are a few different
mostly-simple ways of using txtorcon. They all show how to set up a
connection and then wait for and use various information from Tor.

.. _hello_darkweb.py:

:file:`hello_darkweb.py`
------------------------

:download:`Download the example <../examples/hello_darkweb.py>`.

This is a minimal (but still working) hidden-service set up using the
endpoint parsers (these are Twisted ``IPlugin`` implementations; see
`the documentation
<https://twistedmatrix.com/documents/current/api/twisted.internet.endpoints.serverFromString.html>`_
for more).  It even shows Tor's progress messages on the console.

.. literalinclude:: ../examples/hello_darkweb.py


.. _disallow_streams_by_port.py:

:file:`disallow_streams_by_port.py`
-----------------------------------

:download:`Download the example <../examples/disallow_streams_by_port.py>`.
An example using :class:`~txtorcon.torstate.IStreamAttacher` which is
very simple and does just what it sounds like: never attaches Streams
exiting to a port in the "disallowed" list (it also explicitly closes
them). Note that **Tor already has this feature**; this is just to
illustrate how to use IStreamAttacher and that you may close streams.

.. literalinclude:: ../examples/disallow_streams_by_port.py


.. _launch_tor.py:

:file:`launch_tor.py`
---------------------

:download:`Download the example <../examples/launch_tor.py>`.  Set up
a tor configuration and launch a slave Tor. This takes care of the
setting Tor's notion ownership so that when the control connection
goes away, so does the running Tor.

.. literalinclude:: ../examples/launch_tor.py


.. _launch_tor_endpoint.py:

:file:`launch_tor_endpoint.py`
------------------------------

:download:`Download the example
<../examples/launch_tor_endpoint.py>`. Using the
:class:`txtorcon.TCP4HiddenServiceEndpoint` class to start up a Tor
with a hidden service pointed to an
:api:`twisted.internet.interfaces.IStreamServerEndpoint
<IStreamServerEndpoint>`; fairly similar to
:ref:`launch_tor_with_hiddenservice.py` but more things are automated.

.. literalinclude:: ../examples/launch_tor_endpoint.py


.. _launch_tor_with_hiddenservice.py:

:file:`launch_tor_with_hiddenservice.py`
----------------------------------------

:download:`Download the example
<../examples/launch_tor_with_hiddenservice.py>`. A more complicated
version of the :ref:`launch_tor.py` example where we also set up a
Twisted Web server in the process and have the slave Tor set up a
hidden service configuration pointing to it.

.. literalinclude:: ../examples/launch_tor_with_hiddenservice.py


.. _stream_circuit_logger.py:

:file:`stream_circuit_logger.py`
--------------------------------

:download:`Download the example <../examples/stream_circuit_logger.py>`.
For listening to changes in the Circuit and State objects, this
example is the easiest to understand as it just prints out (some of)
the events that happen. Run this, then visit some Web sites via Tor to
see what's going on.

.. literalinclude:: ../examples/stream_circuit_logger.py


.. _attach_streams_by_country.py:

:file:`circuit_for_next_stream.py`
------------------------------------

:download:`Download the example
<../examples/circuit_for_next_stream.py>`.  This creates a custom
stream specified via router names on the command-line and then
attaches the next new stream the controller sees to this circuit and
exits. A decent custom-circuit example, and a little simpler than the
following example (attach_streams_by_country).

.. literalinclude:: ../examples/circuit_for_next_stream.py


.. _attach_streams_by_country.py:

:file:`attach_streams_by_country.py`
------------------------------------

:download:`Download the example <../examples/attach_streams_by_country.py>`.
This is one of the more complicated examples. It uses a custom Stream
attacher (via :class:`~txtorcon.torstate.IStreamAttacher`) to only attach
Streams to a Circuit with an exit node in the same country as the
server to which the Stream is going (as determined by GeoIP). Caveat:
the DNS lookups go via a Tor-assigned stream, so for sites which use
DNS trickery to get you to a "close" server, this won't be as
interesting. For bonus points, if there is no Circuit exiting in the
correct country, one is created before the Stream is attached.

.. literalinclude:: ../examples/attach_streams_by_country.py


.. _schedule_bandwidth.py:

:file:`schedule_bandwidth.py`
-----------------------------

:download:`Download the example <../examples/schedule_bandwidth.py>`.
This is pretty similar to a feature Tor already has and is basically
useless as-is since what it does is toggle the amount of relay
bandwidth you're willing to carry from 0 to 20KiB/s every 20
minutes. A slightly-more-entertaining way to illustate config
changes. (This is useless because your relay takes at least an hour to
appear in the consensus).

.. literalinclude:: ../examples/schedule_bandwidth.py



.. _dump_config.py:

:file:`dump_config.py`
-----------------------------

:download:`Download the example <../examples/dump_config.py>`.
Very simple read-only use of :class:`txtorcon.TorConfig`

.. literalinclude:: ../examples/dump_config.py




.. _monitor.py:

:file:`monitor.py`
-----------------------------

:download:`Download the example <../examples/monitor.py>`.

Use a plain :class:`txtorcon.TorControlProtocol` instance to listen
for SETEVNET updates. In this case marginally useful, as it listens
for logging things INFO, NOTICE, WARN, ERR.

.. literalinclude:: ../examples/monitor.py




.. _stem_relay_descriptor.py:

:file:`stem_relay_descriptor.py`
--------------------------------

:download:`Download the example <../examples/stem_relay_descriptor.py>`.

Get information about a relay descriptor with the help of `Stem's Relay Descriptor class
<https://stem.torproject.org/api/descriptor/server_descriptor.html#stem.descriptor.server_descriptor.RelayDescriptor>`_.
We need to specify the nickname or the fingerprint to get back
the details.

.. literalinclude:: ../examples/stem_relay_descriptor.py




.. _circuit_failure_rates.py:

:file:`circuit_failure_rates.py`
--------------------------------

:download:`Download the example <../examples/circuit_failure_rates.py>`.

.. literalinclude:: ../examples/circuit_failure_rates.py



.. _txtorcon.tac:

:file:`txtorcon.tac`
--------------------

:download:`Download the example <../examples/txtorcon.tac>`

Create your own twisted `Service` for deploying using ``twistd``.

.. literalinclude:: ../examples/txtorcon.tac

