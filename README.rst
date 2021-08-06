




.. _NOTE: see docs/index.rst for the starting-point
.. _ALSO: https://txtorcon.readthedocs.org for rendered docs






.. image:: https://github.com/meejah/txtorcon/actions/workflows/python3.yaml/badge.svg
    :target: https://github.com/meejah/txtorcon/actions
    :alt: github-actions

.. image:: https://coveralls.io/repos/meejah/txtorcon/badge.png
    :target: https://coveralls.io/r/meejah/txtorcon
    :alt: coveralls

.. image:: http://codecov.io/github/meejah/txtorcon/coverage.svg?branch=main
    :target: http://codecov.io/github/meejah/txtorcon?branch=main
    :alt: codecov

.. image:: https://readthedocs.org/projects/txtorcon/badge/?version=stable
    :target: https://txtorcon.readthedocs.io/en/stable
    :alt: ReadTheDocs

.. image:: https://readthedocs.org/projects/txtorcon/badge/?version=latest
    :target: https://txtorcon.readthedocs.io/en/latest
    :alt: ReadTheDocs

.. image:: https://landscape.io/github/meejah/txtorcon/main/landscape.svg?style=flat
    :target: https://landscape.io/github/meejah/txtorcon/main
    :alt: Code Health


txtorcon
========

- **docs**: https://txtorcon.readthedocs.org or http://timaq4ygg2iegci7.onion
- **code**: https://github.com/meejah/txtorcon
- ``torsocks git clone git://timaq4ygg2iegci7.onion/txtorcon.git``
- MIT-licensed;
- Python 2.7, PyPy 5.0.0+, Python 3.5+;
- depends on
  `Twisted`_,
  `Automat <https://github.com/glyph/automat>`_,
  (and the `ipaddress <https://pypi.python.org/pypi/ipaddress>`_ backport for non Python 3)


Ten Thousand Feet
-----------------

txtorcon is an implementation of the `control-spec
<https://gitweb.torproject.org/torspec.git/blob/HEAD:/control-spec.txt>`_
for `Tor <https://www.torproject.org/>`_ using the `Twisted`_
networking library for `Python <http://python.org/>`_.

This is useful for writing utilities to control or make use of Tor in
event-based Python programs. If your Twisted program supports
endpoints (like ``twistd`` does) your server or client can make use of
Tor immediately, with no code changes. Start your own Tor or connect
to one and get live stream, circuit, relay updates; read and change
config; monitor events; build circuits; create onion services;
etcetera (`ReadTheDocs <https://txtorcon.readthedocs.org>`_).


Some Possibly Motivational Example Code
---------------------------------------

`download <examples/readme.py>`_
(also `python2 style <examples/readme2.py>`_)

.. code:: python

    from twisted.internet.task import react
    from twisted.internet.defer import inlineCallbacks, ensureDeferred
    from twisted.internet.endpoints import UNIXClientEndpoint

    import treq
    import txtorcon


    async def main(reactor):
        tor = await txtorcon.connect(
            reactor,
            UNIXClientEndpoint(reactor, "/var/run/tor/control")
        )

        print("Connected to Tor version {}".format(tor.version))

        url = u'https://www.torproject.org:443'
        print(u"Downloading {}".format(repr(url)))
        resp = await treq.get(url, agent=tor.web_agent())

        print(u"   {} bytes".format(resp.length))
        data = await resp.text()
        print(u"Got {} bytes:\n{}\n[...]{}".format(
            len(data),
            data[:120],
            data[-120:],
        ))

        print(u"Creating a circuit")
        state = await tor.create_state()
        circ = await state.build_circuit()
        await circ.when_built()
        print(u"  path: {}".format(" -> ".join([r.ip for r in circ.path])))

        print(u"Downloading meejah's public key via above circuit...")
        config = await tor.get_config()
        resp = await treq.get(
            u'https://meejah.ca/meejah.asc',
            agent=circ.web_agent(reactor, config.socks_endpoint(reactor)),
        )
        data = await resp.text()
        print(data)


    @react
    def _main(reactor):
        return ensureDeferred(main(reactor))



Try It Now On Debian/Ubuntu
---------------------------

For example, serve some files via an onion service (*aka* hidden
service):

.. code-block:: shell-session

    $ sudo apt-get install --install-suggests python3-txtorcon
    $ twistd -n web --port "onion:80" --path ~/public_html


Read More
---------

All the documentation starts `in docs/index.rst
<docs/index.rst>`_. Also hosted at `txtorcon.rtfd.org
<https://txtorcon.readthedocs.io/en/latest/>`_.

You'll want to start with `the introductions <docs/introduction.rst>`_ (`hosted at RTD
<https://txtorcon.readthedocs.org/en/latest/introduction.html>`_).

.. _Twisted: https://twistedmatrix.com/trac
