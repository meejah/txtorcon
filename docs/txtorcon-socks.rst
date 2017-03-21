.. _socks:

:mod:`txtorcon.socks` Module
============================

SOCKS5 Errors
-------------

SocksError
~~~~~~~~~~
.. autoclass:: txtorcon.socks.SocksError


GeneralServerFailureError
~~~~~~~~~~~~~~~~~~~~~~~~~
.. autoclass:: txtorcon.socks.GeneralServerFailureError


ConnectionNotAllowedError
~~~~~~~~~~~~~~~~~~~~~~~~~
.. autoclass:: txtorcon.socks.ConnectionNotAllowedError


NetworkUnreachableError
~~~~~~~~~~~~~~~~~~~~~~~
.. autoclass:: txtorcon.socks.NetworkUnreachableError


HostUnreachableError
~~~~~~~~~~~~~~~~~~~~
.. autoclass:: txtorcon.socks.HostUnreachableError


ConnectionRefusedError
~~~~~~~~~~~~~~~~~~~~~~
.. autoclass:: txtorcon.socks.ConnectionRefusedError


TtlExpiredError
~~~~~~~~~~~~~~~
.. autoclass:: txtorcon.socks.TtlExpiredError


CommandNotSupportedError
~~~~~~~~~~~~~~~~~~~~~~~~
.. autoclass:: txtorcon.socks.CommandNotSupportedError


AddressTypeNotSupportedError
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. autoclass:: txtorcon.socks.AddressTypeNotSupportedError


Low-level
---------
The following sections present low-level APIs which might change
anytime and break your program. If you are able to work with the
high-level APIs that use these, you should do so. Otherwise, go ahead
as you know what you are doing.


resolve
~~~~~~~
.. autofunction:: txtorcon.socks.resolve


resolve_ptr
~~~~~~~~~~~
.. autofunction:: txtorcon.socks.resolve_ptr


TorSocksEndpoint
~~~~~~~~~~~~~~~~
.. autoclass:: txtorcon.socks.TorSocksEndpoint
