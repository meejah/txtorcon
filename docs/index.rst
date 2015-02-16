.. txtorcon documentation master file, created by
   sphinx-quickstart on Thu Jan 26 13:04:28 2012.

txtorcon
========

txtorcon is a `Twisted <https://twistedmatrix.com/>`_-based `Python
<http://python.org/>`_ asynchronous controller library for `Tor
<https://www.torproject.org/>`_, following `control-spec
<https://gitweb.torproject.org/torspec.git/tree/control-spec.txt>`_.
This would be of interest to anyone wishing to write event-based
software in Python that talks to (and/or launches) a Tor program.

You get real-time access to all state in Tor (circuits, streams,
logging, hidden-services) and utilities to launch or connect to running
Tor instances (including Tor Browser Bundle).

There is a `Walkthrough <walkthrough.html>`_ and `HOWTOs <howtos.html>`_.

The main code is around 2300 lines according to ohcount, or about 5600
lines including tests.

With txtorcon installed, you can use ``"onion:"`` port/endpoint
strings with **any endpoint-aware Twisted program**. For example, to use
Twisted Web to serve your ``~/public_html`` as a hidden service
(``-n`` *means don't daemonize and log to stdout*):

.. code-block:: shell-session

    $ twistd -n web --port "onion:80" --path ~/public_html
    2014-05-30 21:40:23-0600 [-] Log opened.
    #...truncated
    2014-05-30 21:41:16-0600 [TorControlProtocol,client] Tor launching: 90% Establishing a Tor circuit
    2014-05-30 21:41:17-0600 [TorControlProtocol,client] Tor launching: 100% Done
    2014-05-30 21:41:17-0600 [TorControlProtocol,client] Site starting on 46197
    2014-05-30 21:41:17-0600 [TorControlProtocol,client] Starting factory <twisted.web.server.Site instance at 0x7f57667d0cb0>
    2014-05-30 21:41:17-0600 [TorControlProtocol,client] Set up hidden service "2vrrgqtpiaildmsm.onion" on port 80

There's a `complete demonstration <https://asciinema.org/a/10145>`_ at asciinema.org.

Some (other) features and motivating examples:

 - :class:`txtorcon.TorControlProtocol` implements the control-spec protocol (only)
    - see :ref:`monitor.py` which listens for events (SETEVENT ones)

 - :class:`txtorcon.TorState` tracks state for you: all Routers, Streams and Circuits, with listeners
    - see :ref:`stream_circuit_logger.py` which logs all stream and circuit activity

 - :class:`txtorcon.TorConfig` tracks and allows updating of config with attribute-style acccess (including hidden services):
    - :samp:`print config.ORPort`
    - :samp:`config.HiddenServices.append(HiddenService(config, '/hidden/service/dir', ['80 127.0.0.1:1234']))`
    - :samp:`config.SocksPort = 9052`
    - see :ref:`dump_config.py`
    - see also :ref:`launch_tor_with_hiddenservice.py`

 - helpers to launch new slave Tor instances
    - use :class:`txtorcon.TCPHiddenServiceEndpoint` and :api:`twisted.internet.endpoints.serverFromString <serverFromString>` if you can
    - uses TAKEOWNERSHIP and __OwningControllerProcess (killing connection causes Tor to exit)
    - see :ref:`launch_tor.py`
    - see :ref:`launch_tor_with_hiddenservice.py`

 - :class:`txtorcon.TCPHiddenServiceEndpoint` to simplify hidden service listening into Twisteds endpoint paradigm.
    - see :ref:`launch_tor_endpoint.py`


A slight change to the Echo Server example on the front page of
`Twisted's Web site <https://twistedmatrix.com/trac>`_ can make it
appear as a hidden service:

.. code-block:: python

    from __future__ import print_function
    from twisted.internet import protocol, reactor, endpoints

    class Echo(protocol.Protocol):
        def dataReceived(self, data):
            self.transport.write(data)

    class EchoFactory(protocol.Factory):
        def buildProtocol(self, addr):
            return Echo()

    endpoints.serverFromString(reactor, "onion:1234").listen(EchoFactory()).addCallback(lambda x: print(x.getHost()))
    reactor.run()

This is just a one-line change. Note there isn't even an "import
txtorcon" (although it does need to be installed so that Twisted finds
the ``IPlugin`` that does the parsing).


This documentation was generated |today|.

.. image:: https://travis-ci.org/meejah/txtorcon.png?branch=master
    :target: https://www.travis-ci.org/meejah/txtorcon

.. image:: https://coveralls.io/repos/meejah/txtorcon/badge.png
    :target: https://coveralls.io/r/meejah/txtorcon

.. image:: https://pypip.in/d/txtorcon/badge.png
    :target: https://pypi.python.org/pypi/txtorcon


Getting txtorcon:
-----------------

The canonical URI is http://timaq4ygg2iegci7.onion
Code available at https://github.com/meejah/txtorcon

- meejah@meejah.ca (public key: :download:`meejah.asc <../meejah.asc>`)
- ``git clone git://github.com/meejah/txtorcon.git``
- ``pip install txtorcon``
- Watch an `asciinema demo <http://asciinema.org/a/5654>`_ for an overview.


If you're using Debian, txtorcon is now in testing (jessie) and
`wheezy-backports <http://packages.debian.org/source/wheezy-backports/txtorcon>`_ thanks
to Lunar::

    echo "deb http://ftp.ca.debian.org/debian/ wheezy-backports main" >> /etc/apt/sources.list
    apt-get update
    apt-get install python-txtorcon

It also `appears txtorcon is in Gentoo
<http://packages.gentoo.org/package/net-libs/txtorcon>`_ but I don't
use Gentoo (if anyone has a shell-snippet that installs it, send a
pull-request).

**Installing the wheel files** requires a recent pip and
setuptools. At least on Debian, it is important to upgrade setuptools
*before* pip. This procedure appears to work fine::

   virtualenv foo
   . foo/bin/activate
   pip install --upgrade setuptools
   pip install --upgrade pip
   pip install path/to/txtorcon-0.9.0-py27-none-any.whl


Known Users:
------------

 - txtorcon received a brief mention `at 29C3 <http://media.ccc.de/browse/congress/2012/29c3-5306-en-the_tor_software_ecosystem_h264.html>`_ starting at 12:20 (or via `youtube <http://youtu.be/yG2-ci95h78?t=12m27s>`_).
 - `carml <https://github.com/meejah/carml>`_ command-line utilities for Tor
 - `APAF <https://github.com/globaleaks/APAF>`_ anonymous Python application framework
 - `OONI <https://ooni.torproject.org/>`_ the Open Observatory of Network Interference
 - `exitaddr <https://github.com/arlolra/exitaddr>`_ scan Tor exit addresses


Official Releases:
------------------

.. toctree::
   :maxdepth: 2

   releases

Documentation
-------------

.. toctree::
   :maxdepth: 2

   introduction
   howtos
   walkthrough
   README
   examples

API Docs:
---------

.. toctree::
   :maxdepth: 3

   txtorcon

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

