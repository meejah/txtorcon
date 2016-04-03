
.. image:: https://travis-ci.org/meejah/txtorcon.png?branch=master
    :target: https://www.travis-ci.org/meejah/txtorcon

.. image:: https://coveralls.io/repos/meejah/txtorcon/badge.png
    :target: https://coveralls.io/r/meejah/txtorcon

.. image:: http://codecov.io/github/meejah/txtorcon/coverage.svg?branch=master
    :target: http://codecov.io/github/meejah/txtorcon?branch=master

txtorcon
========

- **docs**: https://txtorcon.readthedocs.org or http://timaq4ygg2iegci7.onion
- **code**: https://github.com/meejah/txtorcon
- ``torsocks git clone git://timaq4ygg2iegci7.onion/txtorcon.git``

Brief Overview
--------------

txtorcon is an implementation of the `control-spec
<https://gitweb.torproject.org/torspec.git/blob/HEAD:/control-spec.txt>`_
for `Tor <https://www.torproject.org/>`_ using the `Twisted
<https://twistedmatrix.com/trac/>`_ networking library for `Python
<http://python.org/>`_.

This is useful for writing utilities to control or make use of Tor in
event-based Python programs. If your Twisted program supports
endpoints (like ``twistd`` does) your server or client can make use of
Tor immediately, with no code changes.


Try It Now On Debian/Ubuntu
---------------------------

For example, serve some files via hidden service:

.. code-block:: shell-session

    $ sudo apt-get install python-txtorcon
    $ twistd -n web --port "onion:80" --path ~/public_html


Read More
---------

All the documentation starts `in docs/index.rst
<docs/index.rst>`_. Also hosted at `txtorcon.rtfd.org
<https://txtorcon.readthedocs.org>`_.

You'll want to start with `the overview <docs/overview.rst>`_ (`hosted
<https://txtorcon.readthedocs.org/overview>`_).
