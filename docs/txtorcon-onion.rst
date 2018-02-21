Onion APIs
==========

See the :ref:`programming_guide` for "prose" documentation of these
(and other) APIs.

For non-authenticated services:

IOnionService
-------------
.. autoclass:: txtorcon.IOnionService

IFilesystemOnionService
-----------------------
.. autoclass:: txtorcon.IFilesystemOnionService



Both kinds of authenticated service (ephemeral or disk) implement
these interfaces:

IAuthenticatedOnionClients
--------------------------
.. autoclass:: txtorcon.IAuthenticatedOnionClients

IOnionClient
--------------------------
.. autoclass:: txtorcon.IOnionClient


Concrete classes implementing specific variations of Onion
services. First, ephemeral services (private keys do not live on
disk). See :ref:`server_use` for an overview of the variations.

EphemeralOnionService
----------
.. autoclass:: txtorcon.EphemeralOnionService

EphemeralAuthenticatedOnionService
----------
.. autoclass:: txtorcon.EphemeralAuthenticatedOnionService

EphemeralAuthenticatedOnionServiceClient
----------
.. autoclass:: txtorcon.EphemeralAuthenticatedOnionServiceClient


Onion services which store their secret keys on disk:

FilesystemOnionService
----------
.. autoclass:: txtorcon.FilesystemOnionService

AuthenticatedFilesystemOnionService
----------
.. autoclass:: txtorcon.AuthenticatedFilesystemOnionService

AuthenticatedFilesystemOnionServiceClient
----------
.. autoclass:: txtorcon.AuthenticatedFilesystemOnionServiceClient


Some utility-style classes:

HiddenServiceClientAuth
----------
.. autoclass:: txtorcon.HiddenServiceClientAuth

AuthBasic
---------
.. autoclass:: txtorcon.AuthBasic

AuthStealth
----------
.. autoclass:: txtorcon.AuthStealth

