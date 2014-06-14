HOWTOs
======

Try txtorcon in a Virtualenv
----------------------------

Setting up txtorcon in a virtualenv is a really easy way to play
around with it without "messing up" your system site-packages. If
you're unfamiliar with ``virtualenv``, you can read more `at
readthedocs <http://virtualenv.readthedocs.org/en/latest/>`_.

.. code-block:: shell-session

   $ virtualenv try_txtorcon
   $ . ./try_txtorcon/bin/activate
   $ pip install txtorcon # will install Twisted etc as well
   $ python try_txtorcon/share/txtorcon/examples/circuit_failure_rates.py
   # ...

You can also use the above virtualenv to play with ``twistd`` and
endpoints; see below.

Install txtorcon On Debian
--------------------------

Thanks to work by `Lunar
<http://qa.debian.org/developer.php?login=lunar@debian.org>`_,
txtorcon is usually rapidly packaged into Debian. This means that it
gets into `jessie
<https://packages.debian.org/jessie/python-txtorcon>`_ fairly quickly,
and then arrives in `wheezy-backports
<https://packages.debian.org/wheezy-backports/python-txtorcon>`_ a
couple weeks after that. You can see the current status on the `Debian
QA Page for txtorcon <http://packages.qa.debian.org/t/txtorcon.html>`_

If you're using ``jessie`` (testing), simply:

.. code-block:: shell-session

   $ apt-get install python-txtorcon

For wheezy users, you'll need to enabled the ``wheezy-backports``
repository to Apt. There are `instructions on the Debian wiki
<https://wiki.debian.org/Backports#Adding_the_repository>`_ If you're
in a hurry, you could try this:

.. code-block:: shell-session

   # echo "deb http://ftp.debian.org/debian wheezy-backports main contrib non-free" >> /etc/apt/sources.list
   # apt-get update
   # apt-get install -t wheezy-backports python-txtorcon

.. _howto-endpoint:

Endpoints Enable Tor With Any Twisted Service
---------------------------------------------

As of v0.10.0, there is full support for :api:`twisted.plugin.IPlugin
<IPlugin>`-based endpoint parsers. This adds an ``onion:`` prefix to
the system. (If you're unfamiliar with Twisted's endpoint system,
`read their high-level documentation
<http://twistedmatrix.com/documents/current/core/howto/endpoints.html>`_
first).

So, with txtorcon installed, **any** Twisted program that uses
:api:`twisted.internet.endpoints.serverFromString <serverFromString>`
and lets you pass endpoint strings can cause a new or existing
hidden-service to become available (usually by launching a new Tor
instance).

Twisted's own `twistd
<http://twistedmatrix.com/documents/current/core/howto/basics.html#twistd>`_
provides a Web server out of the box that supports this, so if you
have a collection of documents in ``~/public_html`` you could make
these available via a hidden-service like so (once txtorcon is
installed):

.. code-block:: shell-session

   $ twistd web --port "onion:80" --path ~/public_html

You can look in the ``twistd.log`` file created to determine what the
hidden-serivce keys are. **You must save them** if you want to
re-launch this same onion URI later. If you've done that, you can
(re-)launch a hidden-service with existing keys by adding an argument
to the string:

.. code-block:: shell-session

   $ ls /srv/seekrit/my_service
   hostname private_key
   $ twistd web --port "onion:80:hiddenServiceDir=/srv/seekrit/my_service" --path ~/public_html

See :class:`txtorcon.TCPHiddenServiceEndpointParser` for all the
available options. To test the Web server, you can simply launch with
a local-only server string, like so:

.. code-block::shell-session

   $ twistd web --port "tcp:localhost:8080" --path ~/public_html
   $ curl http://localhost:8080/index.html

If you need more control over the options passed to Tor, you can use
the existing Python APIs to accomplish any Tor configuration and
launching you like (or connect to already-running Tor instances).
