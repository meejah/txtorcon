




.. _NOTE: see docs/index.rst for the starting-point
.. _ALSO: https://txtorcon.readthedocs.org for rendered docs






.. image:: https://travis-ci.org/meejah/txtorcon.png?branch=master
    :target: https://www.travis-ci.org/meejah/txtorcon
    :alt: travis

.. image:: https://coveralls.io/repos/meejah/txtorcon/badge.png
    :target: https://coveralls.io/r/meejah/txtorcon
    :alt: coveralls

.. image:: http://codecov.io/github/meejah/txtorcon/coverage.svg?branch=master
    :target: http://codecov.io/github/meejah/txtorcon?branch=master
    :alt: codecov

.. image:: https://readthedocs.org/projects/txtorcon/badge/?version=latest
    :target: https://txtorcon.readthedocs.io/en/latest/
    :alt: ReadTheDocs

.. image:: https://readthedocs.org/projects/txtorcon/badge/?version=release-1.x
    :target: https://txtorcon.readthedocs.io/en/release-1.x
    :alt: ReadTheDocs

.. image:: http://api.flattr.com/button/flattr-badge-large.png
    :target: http://flattr.com/thing/1689502/meejahtxtorcon-on-GitHub
    :alt: flattr

.. image:: https://landscape.io/github/meejah/txtorcon/master/landscape.svg?style=flat
    :target: https://landscape.io/github/meejah/txtorcon/master
    :alt: Code Health


txtorcon
========

- **docs**: https://txtorcon.readthedocs.org or http://timaq4ygg2iegci7.onion
- **code**: https://github.com/meejah/txtorcon
- ``torsocks git clone git://timaq4ygg2iegci7.onion/txtorcon.git``
- MIT-licensed; Python 2.7, PyPy, 3.4+; depends on `Twisted <https://twistedmatrix.com>`_ (`ipaddress <https://pypi.python.org/pypi/ipaddress>`_ for 2.7)


Ten Thousand Feet
-----------------

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

For example, serve some files via an onion service (*aka* hidden
service):

.. code-block:: shell-session

    $ sudo apt-get install python-txtorcon
    $ twistd -n web --port "onion:80" --path ~/public_html


Read More
---------

All the documentation starts `in docs/index.rst
<docs/index.rst>`_. Also hosted at `txtorcon.rtfd.org
<https://txtorcon.readthedocs.org>`_.

You'll want to start with `the introductions <docs/introduction.rst>`_ (`hosted at RTD
<https://txtorcon.readthedocs.org/en/latest/introduction.html>`_).
