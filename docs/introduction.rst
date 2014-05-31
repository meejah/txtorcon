Introduction
============

txtorcon is an implementation of the `control-spec <URL>`_ for `Tor
<https://www.torproject.org/>`_ using the `Twisted
<https://twistedmatrix.com/trac/>`_ networking library for `Python
<http://python.org/>`_.

This would be of interest to anyone wishing to write event-based
software in Python that talks to a Tor program. Currently, txtorcon is
capable of:

 * maintaining up-to-date state information about Tor (Circuits, Streams and Routers)
 * maintaining current configuration information
 * maintaining representation of Tor's address mappings (with expiry)
 * interrogating initial state of all three of the above
 * listing for and altering stream to circuit mappings
 * building custom circuits
 * Circuit and Stream state listeners
 * uses `GeoIP <https://www.maxmind.com/app/geolitecity>`_ to provide location and ASN information for Routers
 * uses `psutil <http://code.google.com/p/psutil/>`_ (optional) to locate processes creating Streams
 * listening for any Tor EVENT

Comments (positive or negative) appreciated. Even better if they come
with patches.

.. role:: raw-html(raw)
   :format: html

:raw-html:`<script type="text/javascript" src="https://asciinema.org/a/5654.js" id="asciicast-5654" async></script>`

