
txtorcon Programming Guide
==========================

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

 - make client-type connections over tor (see :ref:`client_use`);
 - change its configuration;
 - monitor its state;
 - offer hidden-/onion- services via tor;
 - issue low-level commands

The actual control-protocol connection to tor is abstracted behind
:class:`txtorcon.TorControlProtocol`. This can usually be ignored by
most users, but can be useful to issue protocol commands directly,
listen to raw events, etc.


Connecting to a Running Tor
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Tor can listen for control connections on TCP ports, or UNIX
sockets. See :ref:`configure_tor` for information on how to configure
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


.. _client_use:
Making Connections Over Tor
---------------------------

Tor exposes a SOCKS5 interface to make client-type connections over
the network. We use the ``txsocksx`` library to forward all such
connections over Tor.

All client-side interactions are via instances that implement
`IStreamClientEndpoit`_. There are several factory functions used to
create suitable instances.

The recommended API is to acquire a :class:`txtorcon.Tor` instance
(:ref:`get_tor_instance`) and then call
:meth:`txtorcon.Tor.create_client_endpoint`.

If you need a stream to go over a specific circuit, see XXX:

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
feature of Tor allowing servers (e.g. a Web site) to keep their
network-location hidden. For details of how this works, please read
`Tor's documentation on Hidden Services
<https://www.torproject.org/docs/hidden-services.html.en>`_.

From an API perspective, here are the parts we care about:

 - each service has a secret, private key (with a public part)
   - these keys can be on disk (in the "hidden service directory");
   - or, they can be "ephemeral" (secrets only in memory);
 - the "host name" is a hash of the public-key (e.g. ``timaq4ygg2iegci7.onion``);
 - a "Descriptor" (which tells clients how to connect) must be published;
 - a service has a list of port-mappings (public -> local)
   - e.g. "80 127.0.0.1:5432" says you can contact the service
     publically on port 80, which Tor will redirect to a daemon
     running locally on port ``5432``;
 - services can be "authenticated", which means they have a list of
   client names for which Tor creates associated keys (``.auth_token``).
 - Tor has two flavours of service authentication: ``basic`` and
   ``stealth`` -- there's no API-level difference, but the
   ``.hostname`` is unique for each client in the ``stealth`` case.


Endpoint API
------------

No matter which kind of service you need, you interact via Twisted's
`IStreamServerEndpoint`_ interface. There are various txtorcon methods
(see :ref:`create_onion`) which return some instance implementing that
interface. These instances will also implement
:class:`txtorcon.IProgressProvider` -- which is a hook to register
listerers which get updates about Tor's launching progress (if we
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
------------------------

XXX the easiest to use API are methods of :class:`txtorcon.Tor`, which allow you to create `IStreamServerEndpoint` instances (bring in from other branch).

Both the main endpoint types have several factory-methods to return
instances -- so you first must decide whether to use an
"authenticated" service or not.

 - if you want anyone with e.g. the URL http://timaq4ygg2iegci7.onion
   to be able to put it in `Tor Browser Bundle
   <https://www.torproject.org/download/download.html.en>`_ and see a
   Web site, you **do not want** authentication;
 - if you want only people with the URL *and* a secret authentication
   token to see the Web site, you want **basic** authentication (can
   have many more clients than stealth auth);
 - if you don't even want anyone to be able to decrypt the descriptor
   without the URL and a secret authentication token, you want
   **stealth** authentication (a lot less scalable; for only "a few"
   clients).

Non-Authenticated Services
~~~~~~~~~~~~~~~~~~~~~~~~~~

For non-authenticated services, you want to create a
:class:`txtorcon.TCPHiddenServiceEndpoint` instance.

You can do this via the
:meth:`txtorcon.TCPHiddenServiceEndpoint.create` factory function if
you already have a :class:`TorConfig` instance (or with
:meth:`txtorcon.Tor.create_onion_service()` if you have a
:class:`txtorcon.Tor` instance handy.

Instead, if you don't want to manage launching or connecting to Tor
yourself, you can use one of the three factory methods -- which all
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


Authenticated Services
~~~~~~~~~~~~~~~~~~~~~~

To use authenticated services, you want to create a
:class:`txtorcon.TCPAuthenticatedHiddenServiceEndpoint` instance. This
provides the very same factory methods as for non-authenticatd
instances, but adds arguments for a list of clients (strings) and an
authentication method (``"basic"`` or ``"stealth"``).

For completeness, the methods to create authenticated endpoints are:

 - :meth:`txtorcon.Tor.create_authenticated_onion_service()`;
 - :meth:`txtorcon.TCPAuthenticatedHiddenServiceEndpoint.create`;
 - :meth:`txtorcon.TCPAuthenticatedHiddenSeviceEndpoint.global_tor`
 - :meth:`txtorcon.TCPAuthenticatedHiddenSeviceEndpoint.system_tor`
 - :meth:`txtorcon.TCPAuthenticatedHiddenSeviceEndpoint.private_tor`
