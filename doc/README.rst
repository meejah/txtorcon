txtorcon README
===============

overview
--------

txtorcon is a Python asynchronous controller for Tor based on Twisted,
an event-based networking system for Python. The main abstraction of the
protocol is txtorcon.TorControlProtocol which presents an asynchronous
API to speak the Tor client protocol in Python. txtorcon also provides
abstractions to track and get updates about Tor's state and current
configuration.

My main motivation to write this was to learn more about Twisted and
Tor. I was playing with pyglet and pygame to try out some visualization
ideas and the only Python controller library was synchronous
(thread-based) so I thought I'd write my own

quick implementation overview
-----------------------------

txtorcon also provides a class to track Tor's current state -- such as
details about routers, circuits and streams -- called txtorcon.TorState
and an abstraction to the configuration values via txtorcon.TorConfig
which provides attribute-style accessors to Tor's state (including
making changes). txtorcon.TorState provides txtorcon.Router,
txtorcon.Circuit and txtorcon.Stream objects which implement a listener
interface so client code may receive updates.

txtorcon uses **trial for unit-tests** and has 98% test-coverage --
which is not to say I've covered all the cases, but nearly all of the
code is at least exercised somehow by the unit tests.

::

    $ make test
    Ran 167 tests in 0.412s

    $ make coverage
    ## ...deleted lots of output...
      covered: 1474
    uncovered: 21
    98.58% test coverage

Tor itself is not required to be running for any of the tests. There are
no integration tests.

dependencies
------------

-  `python-ipaddr <http://code.google.com/p/ipaddr-py/>`_: Google's IP
   address manipulation code. Could easily just use string if this
   dependency is a problem; see addrmap.py

-  `twisted <http://twistedmatrix.com>`_: I am working against Twisted
   11.1.0 on Debian with Python 2.7.2.

-  `GeoIP <https://www.maxmind.com/app/python>`_: provides location
   information for ip addresses; you will want to download GeoLite City
   from `MaxMind <https://www.maxmind.com/app/geolitecity>`_ or pay them
   for more accurracy. Or use tor-geoip, which makes this sort-of
   optional, in that we'll query Tor for the if the GeoIP database
   doesn't have an answer but I haven't bothered removing the dependency
   yet..

-  `Sphinx <http://sphinx.pocoo.org/>`_: Only if you want to build the
   documentation.

-  `psutil <http://code.google.com/p/psutil/>`_: optional, used in
   util.process\_from\_address and (if available) for guessing Tor's ip
   if "GETCONF process/pid" isn't available. This makes it a little
   weird for users of process\_from\_address() so might be best just to
   either make it a requirement or not...

In any case, on a `Debian <http://www.debian.org/>`_ or Ubuntu system,
this should work:

::

    apt-get install twisted python-ipaddr python-geoip python-pydoctor python-psutil

documentation
-------------

It is likely that you will need to read at least some of
`control-spec.txt <https://gitweb.torproject.org/torspec.git/blob/HEAD:/control-spec.txt>`_
from the torspec git repository so you know what's being abstracted by
this library.

There is also a directory of examples/ scripts, which have inline
documentation explaining their use. You may also use pydoc:

::

    pydoc txtorcon.TorControlProtocol
    pydoc txtorcon.TorState
    pydoc txtorcon.TorConfig

...for the main classes. If you're using TorState, you will also be
interested in the support classes for it:

::

    pydoc txtorcon.Circuit
    pydoc txtorcon.Stream
    pydoc txtorcon.Router
    pydoc txtorcon.AddrMap

There are also Zope interfaces for some things, if you wish to listen
for events for your own purposes (the best example of the use of these
being TorState itself):

::

    txtorcon.ITorControlProtocol
    txtorcon.IStreamAttacher
    txtorcon.ICircuitListener
    txtorcon.IStreamListener

IStreamAttacher affects Tor's behaviour, allowing one to customize how
circuits for particular streams are selected. You can build your own
circuits via ITorControlProtocol.build\_circuit(). There is an example
of this called custom\_stream\_attacher.py which builds (or uses)
circuits exiting in the same country as the address to which the stream
is connecting (requires geoipdb).

contact information
-------------------

The main Web site for the project, with built documentation and so forth
is at https://timaq4ygg2iegci7.onion although the code itself is hosted
via git:

::

    torsocks git clone git://timaq4ygg2iegci7.onion/txtorcon.git

You may contact me via meejah@meejah.ca with GPG key
`128069A7 <http://pgp.mit.edu:11371/pks/lookup?op=get&search=0xC2602803128069A7>`_
or `local <meejah.asc>`_.
