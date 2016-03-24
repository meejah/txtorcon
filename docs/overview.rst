.. _README:

txtorcon
========

Documentation at https://txtorcon.readthedocs.org or http://timaq4ygg2iegci7.onion
Source code at https://github.com/meejah/txtorcon

.. image:: https://travis-ci.org/meejah/txtorcon.png?branch=master
    :target: https://www.travis-ci.org/meejah/txtorcon

.. image:: https://coveralls.io/repos/meejah/txtorcon/badge.png
    :target: https://coveralls.io/r/meejah/txtorcon

.. image:: http://codecov.io/github/meejah/txtorcon/coverage.svg?branch=master
    :target: http://codecov.io/github/meejah/txtorcon?branch=master

.. image:: http://api.flattr.com/button/flattr-badge-large.png
    :target: http://flattr.com/thing/1689502/meejahtxtorcon-on-GitHub


overview
--------

txtorcon implements a Twisted version of Tor's `control protocol
<https://gitweb.torproject.org/torspec.git/tree/control-spec.txt>`_. On
top of this, txtorcon adds abstractions to examine Tor's live "state"
(active circuits, streams, etc); examine and change Tor's
configuration; add and remove hidden/onion services; launch private
instances of tor; provides Twisted endpoints for clients and (onion)
services; and other utilities.

This allows easy integration of Tor into existing Twisted-using
applications. For example, the endpoints allow you to start an onion
service with *no code changes*. On Debian/Ubuntu, try this to serve
your ``~/public_html`` directory via an onion service:

.. code-block:: shell-session

    $ sudo apt-get install python-txtorcon
    $ twistd -n web --port "onion:80" --path ~/public_html


documentation index
-------------------

txtorcon is a library that other developers will use to make software
which interacts with Tor; as such, the remainder of these docs are
organized around various use-cases and most relevant to fellow
event-based Python developers.


.. toctree::
   :maxdepth: 2

   introduction
   howtos
   walkthrough
   examples
   contact
   hacking

