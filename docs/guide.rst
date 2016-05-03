.. _programming_guide:

Programming Guide
=================

.. contents::
    :depth: 2
    :local:
    :backlinks: none

.. _get_tor_instance:


A Tor Instance
--------------

You will need a connection to a Tor instance for txtorcon to
control. This can be either an already-running tor that you're
authorized to connect to, or a tor instance that has been freshly
launched by txtorcon.

We abstract "a tor instance" behind the :class:`txtorcon.Tor` class,
which provides a very high-level API for all the other things you
might want to do with that Tor:

 - make client-type connections over tor (see ":ref:`guide_client_use`");
 - change its configuration (see ":ref:`guide_configuration`");
 - monitor its state (see ":ref:`guide_state`");
 - offer hidden-/onion- services via tor (see ":ref:``");
 - issue low-level commands (see ":ref:`protocol`")

The actual control-protocol connection to tor is abstracted behind
:class:`txtorcon.TorControlProtocol`. This can usually be ignored by
most users, but can be useful to issue protocol commands directly,
listen to raw events, etc.


Connecting to a Running Tor
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tor can listen for control connections on TCP ports, or UNIX
sockets. See ":ref:`configure_tor`" for information on how to configure
tor to work with txtorcon. By default, "COOKIE" authentication is
used; only if that is not available do we try password authentication.

To connect, use :meth:`txtorcon.Tor.connect` which returns a Deferred
that will fire with a :class:`txtorcon.Tor` instance. If you need
access to the :class:`txtorcon.TorControlProtocol` instance, it's
available via the ``.protocol`` property.


Launching a New Tor
~~~~~~~~~~~~~~~~~~~

It's also possible to launch your own Tor instance. txtorcon keeps a
"global" tor available for use by e.g. the ``.global_tor`` endpoint
factory functions. You can access it via
:meth:`txtorcon.get_global_tor`.

To explicitly launch your own Tor instance, use
:meth:`txtorcon.Tor.launch`. You can pass a couple of minimal options
(``data_directory`` being recommended). If you need to set other Tor
options, use ``.config`` to retrieve the :class:`txtorcon.TorConfig`
instance associated with this tor.

.. _guide_style:

A Note On Style
---------------

Most of txtorcon tends towards "attribute-style access".  The guiding
principle is that "mere data" that is immediately available will be an
attribute, whereas things that "take work" or are async (and thus
return ``Deferred`` s) will be functions. For example,
:meth:`txtorcon.Router.get_location` is a method because it
potentially has to ask Tor for the country, whereas
:attr:`txtorcon.Router.hex_id` is a plain attribute because it's
always available.

Now, in some cases, this may have gotten a little out-of-control. For
example, I'm curious on feedback about whether you like or dislike
:class:`txtorcon.TorConfig`'s use of attribute-style access for Tor
config items...


.. _guide_configuration:

Tracking and Changing Tor's Configuration
-----------------------------------------

Instances of the :class:`txtorcon.TorConfig` class represent the
current, live state of a running Tor. There is a bit of
attribute-magic to make it possible to simply get and set things
easily::

    tor = launch(..)
    print("SOCKS ports: {}".format(tor.config.SOCKSPort))
    tor.config.ControlPort.append(4321)
    tor.config.save()

**Only when** ``.save()`` is called are any ``SETCONF`` commands
issued -- and then, all changed configuration values are sent in a
single command. All ``TorConfig`` instances subscribe to configuration
updates from Tor, so "live state" includes actions by any other
controllers that may be connected.

For some configuration items, the order they're sent to Tor
matters. Sometimes, if you change one config item, you have to set a
series of related items. TorConfig handles these cases for you -- you
just manipulate the configuration, and wait for ``.save()``'s
``Deferred`` to fire and the running tor's configuration is updated.

Note that is a tiny window during which the state may appear slightly
inconsistent: after Tor has acknowledged a ``SETCONF`` command, but
before a separate ``TorConfig`` instance has gotten all the
``CONF_CHANGED`` events (because they're hung up in the networking
stack for some reason). This shouldn't concern most users.

Since :class:`txtorcon.TorConfig` conforms to the Iterator protocol,
you can easily find all the config-options that Tor supports::

    tor = launch(..)
    for config_key in tor.config:
        print("{} has value: {}".format(config_key, getattr(tor.config.config_key)))

These come from interrogating tor using ``GETINFO config/names`` and
so represent the configuration options of the current connected Tor
process. If the value "isn't set" (i.e. is the default), the value
from Tor will be ``txtorcon.DEFAULT_VALUE``.

When you set values into ``TorConfig``, they are parsed according to
control-spec for the different types given to the values, via
information from ``GETINFO config/names``. So, for example, setting
``.SOCKSPort`` to a ``"quux"`` won't work. Of course, it would also
fail the whole ``SETCONF`` command if txtorcon happens to allow some
values that Tor doesn't. Unfortunately, **for any item that's a
list**, Tor doesn't tell us anything about each element so they're all
strings.


.. _guide_state:

Monitor and Change Tor's State
------------------------------

Instances of :class:`txtorcon.TorState` prepresent a live, interactive
version of all the relays/routers (:class:`txtorcon.Router`
instances), all circuits (:class:`txtorcon.Circuit` instances) and
streams (:class:`txtorcon.Stream` instances) active in the underlying
Tor instance.

As the ``TorState`` instance has subscribed to various events from
Tor, the "live" state represents an "as up-to-date as possible"
view.

.. note::

    If you need to be **absolutely sure** there's nothing stuck in
    networking buffers, you can issue a do-nothing command to Tor via
    :meth:`txtorcon.TorControlProtocol.queue_command` (e.g. ``yield
    queue_command("GETINFO version")``). Most users shouldn't have to
    worry about this edge-case.

You can modify the state of these things in a few simple ways. For
example, you can call :meth:`txtorcon.Stream.close` or
:meth:`txtorcon.Circuit.close` to cause a stream or circuit to be
closed. You can wait for a circuit to become usable with
:meth:`txtorcon.Circuit.when_built`.

For a lot of the read-only state, you can simply access interesting
attributes. The relays through which a circuit traverses are in
``Circuit.path`` (a list of :class:`txtorcon.Router` instances),
``Circuit.streams`` contains a list of :class:`txtorcon.Stream`
instances, ``.state`` and ``.purpose`` are strings. ``.time_created``
returns a `datetime
<https://docs.python.org/2/library/datetime.html>`_ instance. There
are also some convenience functions like :meth:`txtorcon.Circuit.age`.

For sending streams over a particular circuit,
:meth:`txtorcon.Circuit.stream_to` returns an `IStreamClientEndpoint`_
implementation that will cause a subsequent ``.connect()`` on it to
go via the given circuit in Tor.

Combined with a :class:`txtorcon.CircuitBuilder` this gives the power
to do many things.

Listening for certain events to happen can be done by implementing the
interfaces :class:`txtorcon.interface.IStreamListener` and
:class:`txtorcon.interface.ICircuitListener`. You can request
notifications on a tor-wide basis with
:meth:`txtorcon.TorState.add_circuit_listener` or
:meth:`txtorcon.TorState.add_stream_listener`. If you are just
interested in a single circuit, you can call
:meth:`txtorcon.Circuit.listen` directly on a ``Circuit`` instance.

(XXX think about the composible-style API; e.g. ``circuit.on('extend',
call_back)`` and/or ``state.on('circuit_extend', call_back)``)

The Tor relays are abstracted with :class:`txtorcon.Router`
instances. Again, these have read-only attributes for interesting
information, e.g.: ``id_hex``, ``ip``, ``flags`` (a list of strings),
``bandwidth``, ``policy``, etc. Note that all information in these
objects is from "microdescriptors". If you're doing a long-running
iteration over relays, it may be important to remember that the
collection of routers can change every hour (when a new "consensus"
from the Directory Authorities is published) which may change the
underlying collection (e.g. :attr:`txtorcon.TorState.routers_by_hash`)
over which you're iterating.

Here's a simple sketch that traverses all circuits printing their
router IDs, and closing each stream and circuit afterwards:

(XXX FIXME test this for realz; can we put it in a "listing"-type
file?)

.. code-block:: python

    @inlineCallbacks
    def main(reactor):
        tor = yield connect(reactor, UNIXClientEndpoint('/var/run/tor/control'))
        state = yield tor.get_state()
        for circuit in state.circuits.values():
            path = '->'.join(map(lambda r: r.id_hex, circuit.streams))
            print("Circuit {} through {}".format(circuit.id, path))
            for stream in circuit.streams:
                print("  Stream {} to {}".format(stream.id, stream.target_host))
                yield stream.close()
            yield circuit.close()


.. _guide_client_use:

Making Connections Over Tor
---------------------------

SOCKS5
~~~~~~

Tor exposes a SOCKS5 interface to make client-type connections over
the network. There are also a couple of `custom extensions
<https://gitweb.torproject.org/torspec.git/tree/socks-extensions.txt>`_
tor provides to do DNS resolution over a Tor circuit (txtorcon
supports these, too).

All client-side interactions are via instances that implement
`IStreamClientEndpoint`_. There are several factory functions used to
create suitable instances.

The recommended API is to acquire a :class:`txtorcon.Tor` instance
(see ":ref:`get_tor_instance`") and then call
:meth:`txtorcon.Tor.create_client_endpoint`. To do DNS lookups (or
reverse lookups) via a Tor circuit, use
:meth:`txtorcon.Tor.dns_resolve` and
:meth:`txtorcon.Tor.dns_resolve_ptr`.

A common use-case is to download a Web resource; you can do so via
Twisted's built-in ``twisted.web.client`` package, or using the
friendlier `treq`_ library. In both cases, you need a
`twisted.web.client.Agent
<https://twistedmatrix.com/documents/current/api/twisted.web.client.Agent.html>`_
instance which you can acquire with :meth:`txtorcon.Tor.web_agent` or
:meth:`txtorcon.Circuit.web_agent`. The latter is used to make the
request over a specific circuit. Usually, txtorcon will simply use one
of the available SOCKS ports configured in the Tor it is connected to
-- if you care which one, you can specify it as the optional
``socks_endpoint=`` argument.

.. note::

   Tor supports SOCKS over Unix sockets. So does txtorcon. To take
   advantage of this, simply pass a valid ``SocksPort`` value for unix
   sockets (e.g. ``unix:/tmp/foo/socks``) as the ``socks_config``
   argument to either ``web_agent()`` call. If this doesn't already
   exist in the underlying Tor, it will be added. Tor has particular
   requirements for the directory in which the socket file is
   (``0700``).

If you need a stream to go over a specific circuit, see
":ref:`circuit_builder`".

(notes to self):

 - CircuitBuilder (for the the open ticket making a higher-level Attacher)
   - a factory/builder that creates Circuit instances
 - Circuit.create_client_endpoint() ? (i.e. makes an endpoint whose streams all go over this circuit)
   - hence can use via TorState or via CircuitBuilder

You can also use Twisted's `clientFromString`_ API as txtorcon
registers a ``tor:`` plugin. This also implies that any Twisted-using
program that supports configuring endpoint strings gets Tor support
"for free". For example, passing a string like
``tor:timaq4ygg2iegci7.onion:80`` to `clientFromString`_ will return
an endpoint that will connect to txtorcon's hidden-service
website. Note that these endpoints will use the "global to txtorcon"
tor instance (available from :meth:`txtorcon.get_global_tor`). Thus,
if you want to control *which* tor instance your circuit goes over,
this is not a suitable API.

There are also lower-level APIs to create
:class:`txtorcon.TorClientEndpoint` instances directly if you have a
:class:`txtorcon.TorConfig` instance. These very APIs are used by the
``Tor`` object mentioned above. If you have a use-case that *requires*
using this API, I'd be curious to learn why the :class:`txtorcon.Tor`
methods are un-suitable (as those are the suggested API).


.. _server_use:

Onion (Hidden) Services
-----------------------

An "Onion Service" (also called a "Hidden Service") refers to a
feature of Tor allowing servers (e.g. a Web site) to get additional
security properties such as: hiding their network location; providing
end-to-end encryption; self-certifying domain-names; or offering
authentication. For details of how this works, please read `Tor's
documentation on Hidden Services
<https://www.torproject.org/docs/hidden-services.html.en>`_.

From an API perspective, here are the parts we care about:

 - each service has a secret, private key (with a corresponding public
   part):
    - these keys can be on disk (in the "hidden service directory");
    - or, they can be "ephemeral" (only in memory);
 - the "host name" is a hash of the public-key (e.g. ``timaq4ygg2iegci7.onion``);
 - a "Descriptor" (which tells clients how to connect) must be published;
 - a service has a list of port-mappings (public -> local)
    - e.g. ``"80 127.0.0.1:5432"`` says you can contact the service
      publically on port 80, which Tor will redirect to a daemon
      running locally on port ``5432``;
    - note that "Descriptors" don't show this information
 - services can be "authenticated", which means they have a list of
   client names for which Tor creates associated keys (``.auth_token``).
 - Tor has two flavours of service authentication: ``basic`` and
   ``stealth`` -- there's no API-level difference, but the
   ``.hostname`` is unique for each client in the ``stealth`` case.
 - See :ref:`create_onion` for details on how to choose which (if any)
   authentication method you'd like

To summarize the above in a table format, here are the possible types
of Onion Service interfaces classes you may interact with (ephemeral
services don't yet support any authentication).

+----------------------------------+--------------------------------------+------------------------+
|                                  | Keys on disk                         | Keys in memory         |
+==================================+======================================+========================+
|      **no authentication**       | IFilesystemOnionService              | IOnionService          |
+----------------------------------+--------------------------------------+------------------------+
| **basic/stealth authentication** | IOnionClients                        |                        |
+----------------------------------+--------------------------------------+------------------------+

Note that it's **up to you to save the private keys** of ephemeral
services if you want to re-launch them later; the "ephemeral" refers
to the fact that Tor doesn't persist the private keys -- when Tor
shuts down, they're gone and there will never be a service at the same
URI again.


Onion Services Endpoints API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

No matter which kind of service you need, you interact via Twisted's
`IStreamServerEndpoint`_ interface. There are various txtorcon methods
(see ":ref:`create_onion`") which return some instance implementing that
interface. These instances will also implement
:class:`txtorcon.IProgressProvider` -- which is a hook to register
listeners which get updates about Tor's launching progress (if we
started a new Tor) and Descriptor uploading.

Fundamentally, "authenticated" services are different from
non-authenticated services because they have a list of
clients. Therefore, there are two different endpoint types:

 - :class:`txtorcon.TCPHiddenServiceEndpoint`
 - :class:`txtorcon.TCPAuthenticatedHiddenServiceEndpoint`

In either case, the ``listen`` method will return an instance
implementing `IListeningPort`_. In addition to `IListeningPort`_,
these instances will implement one of:

 - :class:`txtorcon.IOnionService` or;
 - :class:`txtorcon.IOnionClients`

The first one corresponds to a non-authenticated service, while the
latter is authenticated. The latter manages a collection of instances
by (arbitrary) client names, where each of these instances implements
:class:`txtorcon.IOnionClient` (and therefore also
:class:`txtorcon.IOnionService`). Note that the ``.auth_token`` member
is secret, private data which you need to give to **one** client; this
information goes in the client's Tor configuration as ``HidServAuth
onion-address auth-cookie [service-name]``. See `the Tor manual
<https://www.torproject.org/docs/tor-manual-dev.html.en>`_ for more
information.

Also note that Tor's API for adding "ephemeral" services doesn't yet
support any type of authentication (however, it may in the future).


.. _create_onion:

Creating Onion Endpoints
~~~~~~~~~~~~~~~~~~~~~~~~

The easiest to use API are methods of :class:`txtorcon.Tor`, which
allow you to create `IStreamServerEndpoint` instances for the various
Onion Service types.

Both the main endpoint types have several factory-methods to return
instances -- so you first must decide whether to use an
"authenticated" service or not.

 - if you want anyone with e.g. the URL http://timaq4ygg2iegci7.onion
   to be able to put it in `Tor Browser Bundle
   <https://www.torproject.org/download/download.html.en>`_ and see a
   Web site, you **do not want** authentication;
 - if you want only people with the URL *and* a secret authentication
   token to see the Web site, you want **basic** authentication (these
   support many more clients than stealth auth);
 - if you don't even want anyone to be able to decrypt the descriptor
   without a unique URL *and* a secret authentication token, you want
   **stealth** authentication (a lot less scalable; for only "a few"
   clients).


Non-Authenticated Services
~~~~~~~~~~~~~~~~~~~~~~~~~~

For non-authenticated services, you want to create a
:class:`txtorcon.TCPHiddenServiceEndpoint` instance.

You can do this via the :meth:`txtorcon.create_onion_service` factory
function or with :meth:`txtorcon.Tor.create_onion_service`. It's also
possible to use Twisted's ``clientFromString`` API with the ``onion:``
prefix. (Thus, any program supporting endpoint strings for
configuration can use Tor Onion Services with *no code changes*).

If you don't want to manage launching or connecting to Tor yourself,
you can use one of the three @classmethods on the class, which all
return a new endpoint instance:

 - :meth:`txtorcon.TCPHiddenSeviceEndpoint.global_tor`: uses a Tor
   instance launched at most once in this Python process (the
   underlying :class:`txtorcon.Tor` instance for this is available via
   :meth:`txtorcon.get_global_tor()` if you need to make manual
   configuration adjustments);

 - :meth:`txtorcon.TCPHiddenSeviceEndpoint.system_tor`: connects to
   the control-protocol endpoint you provide (a good choice on Debian
   would be ``UNIXClientEndpoint('/var/run/tor/control')``);

 - :meth:`txtorcon.TCPHiddenSeviceEndpoint.private_tor`: causes a
   fresh, private instance of Tor to be launched for this service
   alone. This uses a tempdir (honoring ``$TMP``) which is deleted
   upon reactor shutdown or loss of the control connection.

Note that nothing actually "happens" until you call ``.listen()`` on
the ``IStreamServerEndpoint`` at which point Tor will possibly be
launched, the Onion Service created, and the descriptor published.


Authenticated Services
~~~~~~~~~~~~~~~~~~~~~~

To use authenticated services, you want to create a
:class:`txtorcon.TCPAuthenticatedHiddenServiceEndpoint` instance. This
provides the very same factory methods as for non-authenticatd
instances, but adds arguments for a list of clients (strings) and an
authentication method (``"basic"`` or ``"stealth"``).

For completeness, the methods to create authenticated endpoints are:

 - :meth:`txtorcon.Tor.create_authenticated_onion_service()`;
 - :meth:`txtorcon.create_authenticated_onion_service`;
 - :meth:`txtorcon.TCPAuthenticatedHiddenSeviceEndpoint.global_tor`
 - :meth:`txtorcon.TCPAuthenticatedHiddenSeviceEndpoint.system_tor`
 - :meth:`txtorcon.TCPAuthenticatedHiddenSeviceEndpoint.private_tor`


Onion Service Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you just want to "look at" the configuration of existing onion
services, they are avaialble via :class:`txtorcon.TorConfig` and the
``.HiddenServices`` attribute.

This presents a "flattened" version of any authenticated services, so
that each element in the list of ``.HiddenServices`` is itself at
least a :class:`txtorcon.IOnionService` (it may also implement other
interfaces, but every one will implement ``IOnionService``).

You can still set any settable attributes on these objects, and Tor's
configuration for them will be updated when you call
:meth:`txtorcon.TorConfig.save` with an **important exception**:
"ephemeral" services cannot be updated after they're created.

Note that it's possible for other controllers to create ephemeral
services that your controller can't enumerate.


Custom Circuits
---------------

txtorcon provides a low-level interface over top of Tor's
circuit-attachment API, which allows you to specify which circuit any
new streams use. Often, though, you also want to create custom
circuits for streams -- and so we also provide a more convenient
higher-level API (see ":ref:`circuit_builder`").

For one-shot connections, use
:meth:`txtorcon.Circuit.create_client_endpoint` to acquire an
``IStreamClientEndpoint`` instance. Calling ``connect()`` on this
endpoint instance causes the resulting stream to go via the particular
:class:`txtorcon.Circuit` instance. (If the circuit has closed by the
time you call ``connect()``, the connection will fail). See
:ref:`example_custom_circuit`.

Note that Tor doesn't currently allow controllers to attach circuits
destined for hidden-services (even over an otherwise suitable circuit).


Building a Single Circuit
~~~~~~~~~~~~~~~~~~~~~~~~~

If your use-case needs just a single circuit, it is probably easiest
to call :meth:`txtorcon.TorState.build_circuit`. This methods takes a
list of :class:`txtorcon.Router` instances, which you can get from the
:class:`txtorcon.TorState` instance by using one of the attributes:

 - ``.all_routers``
 - ``.routers``
 - ``.routers_by_name`` or
 - ``.routers_by_hash``

The last three are all hash-tables. For relays that have the ``Guard``
flag, you can access the hash-tables ``.guards`` (for **all** of them)
or ``.entry_guards`` (for just the entry guards configured on this Tor
client).

If you don't actually care which relays are used, but simply want a
fresh circuit, you can call :meth:`txtorcon.TorState.build_circuit`
without any arguments (or, set ``routers=None``).


.. _circuit_builder:

Building Many Circuits
~~~~~~~~~~~~~~~~~~~~~~

If you would like to build many circuits, you'll want an instance that
implements :class:`txtorcon.ICircuitBuilder` (which is usually simply
an instance of :class:`txtorcon.CircuitBuilder`). Instances of this
class can be created by calling one of the factory functions like
:func:`txtorcon.circuit_builder_fixed_exit`.

XXX what about a "config object" idea, e.g. could have keys:

 - ``guard_selection``: one of ``entry_only`` (use one of the current
   entry guards) or ``random_guard`` (use any relay with the Guard
   flag, selected by XXX).
 - ``middle_selection``: one of ``uniform`` (selected randomly from
   all relays), ``weighted`` (selected randomly, but weighted by
   consensus weight -- basically same way as Tor would select).


Attaching Streams to Circuits
-----------------------------

Tor allows the controller to decide how to attach new streams to
circuits. This doesn't work for hidden-service bound streams. The
lower-level API is to implement an :class:`txtorcon.IStreamAttacher`
and call :meth:`txtorcon.TorState.set_stream_attacher` on your
``TorState`` instance.

Often, however, making low-level per-stream decisions isn't what you
want -- you just want to create a stream that goes over a particular
circuit. For this use-case, you use :meth:`txtorcon.Circuit`.

.. _istreamclientendpoint: http://twistedmatrix.com/documents/current/api/twisted.internet.interfaces.IStreamClientEndpoint.html
.. _istreamserverendpoint: http://twistedmatrix.com/documents/current/api/twisted.internet.interfaces.IStreamServerEndpoint.html
.. _clientfromstring: http://twistedmatrix.com/documents/current/api/twisted.internet.endpoints.html#clientFromString
.. _serverfromstring: http://twistedmatrix.com/documents/current/api/twisted.internet.endpoints.html#serverFromString
.. _ilisteningport: http://twistedmatrix.com/documents/current/api/twisted.internet.interfaces.IListeningPort.html
.. _treq: https://github.com/twisted/treq
