txtorcon README
===============

Full documentation at ReadTheDocs http://txtorcon.rtfd.org

overview
--------

txtorcon is a Twisted-based asynchronous Tor control protocol
implementation. Twisted is an event-driven networking engine written in
Python and Tor is an onion-routing network designed to improve people's
privacy and security on the Internet.

The main abstraction of this library is txtorcon.TorControlProtocol
which presents an asynchronous API to speak the Tor client protocol in
Python. txtorcon also provides abstractions to track and get updates
about Tor's state (txtorcon.TorState) and current configuration
(including writing it to Tor or disk) in txtorcon.TorConfig, along with
helpers to asynchronously launch slave instances of Tor including
Twisted endpoint support.

My main motivation to write this was to learn more about Twisted and
Tor. I was playing with pyglet and pygame to try out some visualization
ideas and the only Python controller library was synchronous
(thread-based) so I thought I'd write my own.

NOTE: that this is currently a moving target still; if you're going to
depend on txtorcon as a controller library, it Very Highly Recommended
that you follow the source at github (or via the hidden service). I
fairly regularly push code to both.

txtorcon runs all test cleanly on both Debian stable (squeeze) and
testing (wheezy). Reports from other OSes appreciated.

If instead you want a synchronous Python controller library, check out
Stem at http://stem.readthedocs.org/en/latest/

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
    Ran 186 tests in 0.426s

    $ make coverage
    ## ...deleted lots of output...
    covered: 1675
    uncovered: 57
    96.60% test coverage

Tor itself is not required to be running for any of the tests. There are
no integration tests. ohcount claims under 2000 lines of code for the
core bit; around 4000 including tests.

I would also **note** that I was experimenting with underscores instead
of camelCase for the method names; since Twisted is camelCase it might
make sense to switch especially if anyone has strong feelings on this.
On the other hand, it makes it obvious which calls are Twisted and which
are txtorcon.

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
   for more accuracy. Or use tor-geoip, which makes this sort-of
   optional, in that we'll query Tor for the if the GeoIP database
   doesn't have an answer but I haven't bothered removing the dependency
   yet..It also does ASN lookups if you installed that MaxMind database.

-  `Sphinx <http://sphinx.pocoo.org/>`_: Only if you want to build the
   documentation. In that case you'll also need something called
   ``python-repoze.sphinx.autointerface`` (at least in Debian) to build
   the Interface-derived docs properly.

-  GraphViz is used in the tests (and to generate state-machine
   diagrams, if you like). If you don't have/want it see
   ``txtorcon/test/test_fsm.py`` around line 62 to disable the test

In any case, on a `Debian <http://www.debian.org/>`_ wheezy or Ubuntu
system, this should work:

::

    apt-get install python-setuptools python-twisted python-ipaddr python-geoip graphviz
    apt-get install python-sphinx python-repoze.sphinx.autointerface # for documentation

documentation
-------------

**FIXME** **NOTE** I'm planning to possibly re-organize which .py files
the classes are in. If you know some best practices on this, or have
specific suggestions please email me.

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

For launching Tor and Twisted integration, you will want to look at:

::

    txtorcon.launch_tor (in torconfig.py)
    txtorcon.TCPHiddenServiceEndpoint (in torconfig.py)
    txtorcon.build_tor_connection (in torstate.py)
    txtorcon.TorProtocolFactory (in torcontrolprotocol.py)

IStreamAttacher affects Tor's behaviour, allowing one to customize how
circuits for particular streams are selected. You can build your own
circuits via ITorControlProtocol.build\_circuit(). There is an example
of this called custom\_stream\_attacher.py which builds (or uses)
circuits exiting in the same country as the address to which the stream
is connecting.

contact information
-------------------

For novelty value, the Web site (with built documentation and so forth)
can be viewed via Tor at https://timaq4ygg2iegci7.onion although the
code itself is hosted via git:

::

    torsocks git clone git://timaq4ygg2iegci7.onion/txtorcon.git

You may contact me via meejah@meejah.ca with GPG key
``128069A7 <http://pgp.mit.edu:11371/pks/lookup?op=get&search=0xC2602803128069A7>``\ \_
or see ``meejah.asc``. It is often possible to contact me as ``meejah``
in #tor-dev on ``OFTC <http://www.oftc.net/oftc/>``\ \_ but be patient
for replies (I do look at scrollback, so mention my nick).

More conventionally, you may get the code at GitHub and documentation
via ReadTheDocs:

-  https://github.com/meejah/txtorcon
-  http://readthedocs.org/docs/txtorcon/en/latest/

Please do use the GitHub issue-tracker to report bugs. Patches,
comments, criticisms all welcomed and appreciated. See TODO for notes on
deficiencies, planned features, lunatic raving, etc.
