.. txtorcon documentation master file, created by
   sphinx-quickstart on Thu Jan 26 13:04:28 2012.

txtorcon
========

txtorcon is a `Twisted <https://twistedmatrix.com/>`_-based `Python
<http://python.org/>`_ asynchronous controller library for `Tor
<https://www.torproject.org/>`_, following `control-spec
<https://gitweb.torproject.org/torspec.git/blob/HEAD:/control-spec.txt>`_.
This would be of interest to anyone wishing to write event-based
software in Python that talks to a Tor program.

**Cut to the chase** by perusing the `Walkthrough <walkthrough.html>`_.

The main code is under 2000 lines according to ohcount, or 4500 lines
including tests. Some features and motivating examples:

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
    - uses TAKEOWNERSHIP and __OwningControllerProcess (killing connection causes Tor to exit)
    - see :ref:`launch_tor.py`
    - see :ref:`launch_tor_with_hiddenservice.py`

 - :class:`txtorcon.TCPHiddenServiceEndpoint` to simplify hidden service listening into Twisteds endpoint paradigm.
    - see :ref:`launch_tor_endpoint.py`

This documentation was generated |today|.

.. image:: https://travis-ci.org/meejah/txtorcon.png?branch=master
    :target: https://www.travis-ci.org/meejah/txtorcon

.. image:: https://coveralls.io/repos/meejah/txtorcon/badge.png
    :target: https://coveralls.io/r/meejah/txtorcon

.. image:: https://pypip.in/d/txtorcon/badge.png
    :target: https://crate.io/packages/txtorcon


Getting txtorcon:
-----------------

The canonical URI is http://timaq4ygg2iegci7.onion
Code available at https://github.com/meejah/txtorcon

- meejah@meejah.ca (public key: :download:`meejah.asc <../meejah.asc>`)
- ``git clone git://github.com/meejah/txtorcon.git``
- **``pip install txtorcon``**
- Watch an `asciinema demo <http://asciinema.org/a/5654>`_ for an overview.


If you're using Debian, txtorcon is now in testing (jessie) and
`wheezy-backports <http://packages.debian.org/source/wheezy-backports/txtorcon>`_ thanks
to Lunar::

    echo "deb http://ftp.ca.debian.org/debian/ wheezy-backports main" >> /etc/apt/sources.list
    apt-get update
    apt-get install python-txtorcon 


Known Users:
------------

 - txtorcon received a brief mention `at 29C3 <http://media.ccc.de/browse/congress/2012/29c3-5306-en-the_tor_software_ecosystem_h264.html>`_ starting at 12:20 (or via `youtube <http://youtu.be/yG2-ci95h78?t=12m27s>`_).
 - `APAF <https://github.com/globaleaks/APAF>`_ anonymous Python application framework
 - `OONI <https://ooni.torproject.org/>`_ the Open Observatory of Network Interference


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

