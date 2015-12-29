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
gets into `stretch
<https://packages.debian.org/stretch/python-txtorcon>`_ fairly quickly,
and then arrives in `jessie-backports
<https://packages.debian.org/jessie-backports/python-txtorcon>`_ a
couple weeks after that. You can see the current status on the `Debian
QA Page for txtorcon <http://packages.qa.debian.org/t/txtorcon.html>`_

If you're using ``stretch`` (testing), simply:

.. code-block:: shell-session

   $ apt-get install python-txtorcon

If you're using wheezy, it should "just work".  For jessie users,
you'll probably want to enabled the ``jessie-backports`` repository to
Apt. There are `instructions on the Debian wiki
<https://wiki.debian.org/Backports#Adding_the_repository>`_ If you're
in a hurry, you could try this:

.. code-block:: shell-session

   # echo "deb http://ftp.debian.org/debian jessie-backports main contrib non-free" >> /etc/apt/sources.list
   # apt-get update
   # apt-get install -t jessie-backports python-txtorcon

.. _howto-endpoint:


Endpoints Enable Tor With Any Twisted Service
---------------------------------------------

.. raw:: html

   <div style="margin-left: 3em;"><script type="text/javascript" src="https://asciinema.org/a/10145.js" id="asciicast-10145" async></script></div>

(or view `directly on asciienma.org <https://asciinema.org/a/10145>`_).

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

To find out your service's hostname and where the private key is
located, look in the ``twistd.log`` file, which will look something
like this (trunacted for space):

.. code-block:: shell-session

   ...
   2014-06-13 23:48:39-0600 [-] Spawning tor process from: /tmp/tortmpkh4bsM
   2014-06-13 23:48:40-0600 [TorControlProtocol,client] 10% Finishing handshake with directory server
   ...
   2014-06-13 23:48:53-0600 [TorControlProtocol,client] 90% Establishing a Tor circuit
   2014-06-13 23:48:54-0600 [TorControlProtocol,client] 100% Done
   2014-06-13 23:48:54-0600 [TorControlProtocol,client] Site starting on 48275
   2014-06-13 23:48:54-0600 [TorControlProtocol,client] Starting factory <twisted.web.server.Site instance at 0x7f1b6753e710>
   2014-06-13 23:48:54-0600 [TorControlProtocol,client] Started hidden service "rv5gkzutsh2k5bzg.onion" on port 80
   2014-06-13 23:48:54-0600 [TorControlProtocol,client] Keys are in "/tmp/tortmpoeZJYC".

See :class:`txtorcon.TCPHiddenServiceEndpointParser` for all the
available options. To test the Web server, you can simply launch with
a local-only server string, like so:

.. code-block:: shell-session

   $ twistd web --port "tcp:localhost:8080" --path ~/public_html
   $ curl http://localhost:8080/index.html

If you need more control over the options passed to Tor, you can use
the existing Python APIs to accomplish any Tor configuration and
launching you like (or connect to already-running Tor instances).

Although Twisted Matrix themselves don't recommend doing "Web
development" with Twisted, the Twisted Web server is a robust provider
of HTTP and HTTPS services. It also supports WSGI so can easily front
a Python-based Web application (e.g. Django or Flask).

``twistd`` provides several other services as well; see `twistd(1)
<http://linux.die.net/man/1/twistd>`_ for more information.
