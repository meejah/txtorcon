.. _installing:

Installing txtorcon
===================

Latest Release
--------------

txtorcon is on PyPI and in Debian since `jessie
<https://packages.debian.org/jessie/python-txtorcon>`_ (thanks to
Lunar!). So, one of these should work:

- install latest release: ``pip install txtorcon``
- Debian or Ubuntu: ``apt-get install python-txtorcon``
- Watch an `asciinema demo <http://asciinema.org/a/5654>`_ for an overview.

Rendered documentation for the latest release is at
`txtorcon.readthedocs.org <https://txtorcon.readthedocs.org/en/latest/>`_. What exists for
release-notes are in ":ref:`releases`".

If you're still using wheezy, ``python-txtorcon`` is also in `wheezy-backports <http://packages.debian.org/source/wheezy-backports/txtorcon>`_.

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
   pip install path/to/txtorcon-*.whl


Compatibility
-------------

txtorcon runs all tests cleanly under Python2 and PyPy on:

  -  Debian: "squeeze", "wheezy" and "jessie"
  -  OS X: 10.4 (naif), 10.8 (lukas lueg), 10.9 (kurt neufeld)
  -  Fedora 18 (lukas lueg)
  -  FreeBSD 10 (enrique fynn) (**needed to install "lsof"**)
  -  RHEL6
  -  **Reports from other OSes appreciated.**

Python3 support is "nearly there", except for the client-side
endpoints which depend on ``txsocksx``, which is not ported to
Python3.


Tor Configuration
-----------------

Using Tor's cookie authentication is the most convenient way to
connect; this proves that your user can read a cookie file written by
Tor. To enable this, you'll want to have the following options on in
your ``torrc``::

   CookieAuthentication 1
   CookieAuthFileGroupReadable 1

Note that "Tor BrowserBundle" is configured this way by default, on
port 9151.  If you want to use unix sockets to speak to tor (highly
recommended)::

   ControlSocketsGroupWritable 1
   ControlSocket /var/run/tor/control

The defaults used by py:meth:`txtorcon.build_local_tor_connection` will
find a Tor on ``9051`` or ``/var/run/tor/control``


Source Code
-----------

Most people will use the code from https://github.com/meejah/txtorcon
The canonical URI is http://timaq4ygg2iegci7.onion
I sign tags with my public key (:download:`meejah.asc <../meejah.asc>`)

- code: ``git clone git://github.com/meejah/txtorcon.git``

Rendered documentation for the latest release is at
`txtorcon.readthedocs.org
<https://txtorcon.readthedocs.org/en/latest/>_`.

See :ref:`hacking` if you wish to contribute back to txtorcon :)


Development Environment
-----------------------

I like to set up my Python development like this:

.. code-block:: shell-session

    $ git clone git://github.com/meejah/txtorcon.git
    # if you later clone it on github, do this:
    $ git remote add -f github git://github.com/<my github handle>/txtorcon.git
    $ cd txtorcon
    $ virtualenv venv
    $ source venv/bin/activate
    (venv)$ pip install --editable .[dev]  # "dev" adds more deps, like Sphinx
    (venv)$ make doc
    (venv)$ make test
    (venv)$ tox  # run all tests, in all supported configs

You can now edit code in the repository as normal. To submit a patch,
the easiest way is to "clone" the txtxtcon project, and add a remote
called "github" (``git remote add -f github git://github.com/<my
github handle>/txtorcon.git``). The ``-f`` is so you don't have to
``git fetch`` right after.

Now, you can push a new branch you've made to GitHub with ``git push
github branch-name`` and then examine it and open a pull-request. This
will trigger Travis to run the tests, after which coverage will be
produced (and a bot comments on the pull-request). If you require any
more changes, the easiest thing to do is just commit them and push
them. (If you know how, re-basing/re-arranging/squashing etc is nice
to do too).


Integration Tests
-----------------

There are a couple of simple integration tests using Docker in the
``integration/`` directory; these make a ``debootstrap``-built base
image and then do the test inside containers cloned from this -- no
trusting ``https://docker.io`` required. See ``integration/README``
for more information.

If you're on Debian, there's a decent chance running ``make
txtorcon-tester`` followed by ``make integration`` from the root of
the checkout will work (the first commands ultimately runs
``debootstrap`` and some ``apt`` commands besides ``docker`` things).


Dependencies / Requirements
---------------------------

These should have been installed by whichever method you chose above,
but are listed here for completeness. You can get all the development
requirements with e.g. ``pip install txtorcon[dev]``.

- `twisted <http://twistedmatrix.com>`_: txtorcon should work with any
   Twisted 11.1.0 or newer. Twisted 15.4.0+ works with Python3, and so
   does txtorcon (if you find something broken on Py3 please file a bug).

-  `GeoIP <https://www.maxmind.com/app/python>`_: **optional** provides location
   information for ip addresses; you will want to download GeoLite City
   from `MaxMind <https://www.maxmind.com/app/geolitecity>`_ or pay them
   for more accuracy. Or use tor-geoip, which makes this sort-of
   optional, in that we'll query Tor for the IP if the GeoIP database
   doesn't have an answer. It also does ASN lookups if you installed that MaxMind database.

-  development: `Sphinx <http://sphinx.pocoo.org/>`_ if you want to build the
   documentation. In that case you'll also need something called
   ``python-repoze.sphinx.autointerface`` (at least in Debian) to build
   the Interface-derived docs properly.

-  development: `coverage <http://nedbatchelder.com/code/coverage/>`_ to
   run the code-coverage metrics, and Tox

-  optional: GraphViz is used in the tests (and to generate state-machine
   diagrams, if you like) but those tests are skipped if "dot" isn't
   in your path

.. BEGIN_INSTALL

In any case, on a `Debian <http://www.debian.org/>`_ wheezy, squeeze or
Ubuntu system, this should work::

    apt-get install -y python-setuptools python-twisted python-ipaddr python-geoip graphviz tor
    apt-get install -y python-sphinx python-repoze.sphinx.autointerface python-coverage # for development

.. END_INSTALL

Using pip this would be::

    pip install Twisted ipaddr pygeoip
    pip install GeoIP Sphinx repoze.sphinx.autointerface coverage  # for development

or::

    pip install -r requirements.txt
    pip install -r dev-requirements.txt

or for the bare minimum::

    pip install Twisted  # will install zope.interface too

