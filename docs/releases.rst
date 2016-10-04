Releases
========

There isn't a "release schedule" in any sense. If there is something
in master your project depends upon, let me know and I'll do a
release. Starting with v0.8.0 versions are following `semantic
versioning <http://semver.org/>`_.

release-1.x
-----------

A branch is in development fixing, updating and/or breaking some APIs
and adding a new object to represent the running tor instance and a
completel documentation re-write. This is not ready for release quite
yet, but feedback appreciated, especially on the documentation!
Rendered docs on `txtorcon.readthedocs <http://txtorcon.readthedocs.io/en/release-1.x/>`_.


unreleased
----------

`git master <https://github.com/meejah/txtorcon>`_ *will likely become v0.18.0*


v0.17.0
-------

*October 4, 2016*

 * `txtorcon-0.17.0.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.17.0.tar.gz>`_ (`PyPI <https://pypi.python.org/pypi/txtorcon/0.17.0>`_ (:download:`local-sig </../signatues/txtorcon-0.17.0.tar.gz.asc>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.17.0.tar.gz.asc?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.17.0.tar.gz>`_)
 * `issue 187 <https://github.com/meejah/txtorcon/issues/187>`_: fix unix-socket control endpoints
 * sometimes mapping streams to hostnames wasn't working properly
 * backwards-compatibility API for `socks_hostname` was incorrectly named


v0.16.1
-------

*August 31, 2016*

 * `txtorcon-0.16.1.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.16.1.tar.gz>`_ (`PyPI <https://pypi.python.org/pypi/txtorcon/0.16.1>`_ (:download:`local-sig </../signatues/txtorcon-0.16.1.tar.gz.asc>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.16.1.tar.gz.asc?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.16.1.tar.gz>`_)
 * `issue 172 <https://github.com/meejah/txtorcon/issues/172>`_: give `TorProcessProtocol` a `.quit` method
 * `issue 181 <https://github.com/meejah/txtorcon/issues/181>`_: enable SOCKS5-over-unix-sockets for TorClientEndpoint (thanks to `david415 <https://github.com/david415>`_


v0.16.0
-------

 * there wasn't one, `because reasons <https://github.com/meejah/txtorcon/commit/e4291c01ff223d3cb7774437cafa2f06ca195bcf>`_.


v0.15.1
-------

 * `txtorcon-0.15.1.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.15.1.tar.gz>`_ (`PyPI <https://pypi.python.org/pypi/txtorcon/0.15.1>`_ (:download:`local-sig </../signatues/txtorcon-0.15.1.tar.gz.asc>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.15.1.tar.gz.asc?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.15.1.tar.gz>`_)
 * fix `issue 179 <https://github.com/meejah/txtorcon/issues/179>`_ with `Circuit.age`.


v0.15.0
-------

*July 26, 2016*

 * `txtorcon-0.15.0.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.15.0.tar.gz>`_ (`PyPI <https://pypi.python.org/pypi/txtorcon/0.15.0>`_ (:download:`local-sig </../signatues/txtorcon-0.15.0.tar.gz.asc>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.15.0.tar.gz.asc?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.15.0.tar.gz>`_)
 * added support for NULL control-port-authentication which is often
   appropriate when used with a UNIX domain socket
 * switched to `ipaddress
   <https://docs.python.org/3/library/ipaddress.html>`_ instead of
   Google's ``ipaddr``; the API should be the same from a user
   perspective but **packagers and tutorials** will want to change
   their instructions slightly (``pip install ipaddress`` or ``apt-get
   install python-ipaddress`` are the new ways).
 * support the new ADD_ONION and DEL_ONION "ephemeral hidden services"
   commands in TorConfig
 * a first stealth-authentication implementation (for "normal" hidden
   services, not ephemeral)
 * bug-fix from `david415 <https://github.com/david415>`_ to raise
   ConnectionRefusedError instead of StopIteration when running out of
   SOCKS ports.
 * new feature from `david415 <https://github.com/david415>`_ adding a
   ``build_timeout_circuit`` method which provides a Deferred that
   callbacks only when the circuit is completely built and errbacks if
   the provided timeout expires. This is useful because
   :doc:`TorState.build_circuit` callbacks as soon as a Circuit
   instance can be provided (and then you'd use
   :doc:`Circuit.when_built` to find out when it's done building).
 * new feature from `coffeemakr <https://github.com/coffeemakr>`_
   falling back to password authentication if cookie authentication
   isn't available (or fails, e.g. because the file isn't readable).
 * both TorState and TorConfig now have a ``.from_protocol`` class-method.
 * spec-compliant string-un-escaping from `coffeemakr <https://github.com/coffeemakr>`_
 * a proposed new API: :meth:`txtorcon.connect`
 * fix `issue 176 <https://github.com/meejah/txtorcon/issues/176>`_


v0.14.1
-------

*October 25, 2015*

 * subtle bug with ``.is_built`` on Circuit; changing the API (but
   with backwards-compatibility until 0.15.0 at least)


v0.14.0
-------

*September 26, 2015*

 * `txtorcon-0.14.0.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.14.0.tar.gz>`_ (`PyPI <https://pypi.python.org/pypi/txtorcon/0.14.0>`_ (:download:`local-sig </../signatues/txtorcon-0.14.0.tar.gz.asc>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.14.0.tar.gz.asc?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.14.0.tar.gz>`_)
 * :class:`txtorcon.interface.IStreamAttacher` handling was missing ``None`` and ``DO_NOT_ATTACH`` cases if a Deferred was returned.
 * add ``.is_built`` Deferred to :class:`txtorcon.Circuit` that gets `callback()`d when the circuit becomes BUILT
 * `david415 <https://github.com/david415>`_ ported his ``tor:``
   endpoint parser so now both client and server endpoints are
   supported. This means **any** Twisted program using endpoints can
   use Tor as a client. For example, to connect to txtorcon's Web site:
   ``ep = clientFromString("tor:timaq4ygg2iegci7.onion:80")``.
   (In the future, I'd like to automatically launch Tor if required, too).
 * Python3 fixes from `isis <https://github.com/isislovecruft>`_ (note: needs Twisted 15.4.0+)


v0.13.0
-------

*May 10, 2015*

 * `txtorcon-0.13.0.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.13.0.tar.gz>`_ (`PyPI <https://pypi.python.org/pypi/txtorcon/0.13.0>`_ (:download:`local-sig </../signatues/txtorcon-0.13.0.tar.gz.asc>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.13.0.tar.gz.asc?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.13.0.tar.gz>`_)
 * support ``basic`` and ``stealth`` hidden service authorization, and parse ``client_keys`` files.
 * 2x speedup for TorState parsing (mostly by lazy-parsing timestamps)
 * can now parse ~75000 microdescriptors/second per core of 3.4GHz Xeon E3
 * ``launch_tor`` now doesn't use a temporary ``torrc`` (command-line options instead)
 * tons of pep8 cleanups
 * several improvements to hidden-service configuration from `sambuddhabasu1`_.
 * populated valid signals from ``GETINFO signals/names`` from `sambuddhabasu1`_.

.. _sambuddhabasu1: https://github.com/sammyshj


v0.12.0
-------

*February 3, 2015*

 * `txtorcon-0.12.0.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.12.0.tar.gz>`_ (`PyPI <https://pypi.python.org/pypi/txtorcon/0.12.0>`_ (:download:`local-sig </../signatues/txtorcon-0.12.0.tar.gz.asc>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.12.0.tar.gz.asc?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.12.0.tar.gz>`_)
 * doc, code and import cleanups from `Kali Kaneko <https://github.com/kalikaneko>`_
 * HiddenServiceDirGroupReadable support
 * Issue #80: honour ``ControlPort 0`` in incoming TorConfig
   instance. The caller owns both pieces: you have to figure out when
   it's bootstraped, and are responsible for killing it off.
 * Issue #88: clarify documentation and fix appending to some config lists
 * If GeoIP data isn't loaded in Tor, it sends protocol errors; if
   txtorcon also hasn't got GeoIP data, the queries for country-code
   fail; this error is now ignored.
 * **100% unit-test coverage!** (line coverage)
 * PyPy support (well, at least all tests pass)
 * TCP4HiddenServiceEndpoint now waits for descriptor upload before
   the ``listen()`` call does its callback (this means when using
   ``onion:`` endpoint strings, or any of the :doc:`endpoints APIs
   <txtorcon-endpoints>` your hidden service is 100% ready for action
   when you receive the callback)
 * ``TimeIntervalCommaList`` from Tor config supported
 * :class:`TorControlProtocol <txtorcon.TorControlProtocol>` now has a ``.all_routers`` member (a ``set()`` of all Routers)
 * documentation fix from `sammyshj <https://github.com/sammyshj>`_


v0.11.0
-------

*August 16, 2014*

 * September 6, 2015. bugfix release: `txtorcon-0.11.1.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.11.1.tar.gz>`_ (`PyPI <https://pypi.python.org/pypi/txtorcon/0.11.1>`_ (:download:`local-sig </../signatues/txtorcon-0.11.1.tar.gz.asc>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.11.1.tar.gz.asc?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.11.1.tar.gz>`_)
 * fixed Debian bug `797261 <https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=797261>`_ causing 3 tests to fail
 * `txtorcon-0.11.0.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.11.0.tar.gz>`_ (`PyPI <https://pypi.python.org/pypi/txtorcon/0.11.0>`_ (:download:`local-sig </../signatues/txtorcon-0.11.0.tar.gz.asc>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.11.0.tar.gz.asc?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.11.0.tar.gz>`_) 
 * More control for ``launch_tor``: access stdout, stderr in real-time
   and control whether we kill Tor on and stderr output. See issue #79.
 * Warning about ``build_circuit`` being called without a guard first
   is now optional (default is still warn) (from arlolra_)
 * ``available_tcp_port()`` now in util (from arlolra_)
 * ``TorState`` now has a ``.routers_by_hash`` member (from arlolra_)

.. _arlolra: https://github.com/arlolra

v0.10.1
-------

*July 20, 2014*

 * `txtorcon-0.10.1.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.10.1.tar.gz>`_ (`PyPI <https://pypi.python.org/pypi/txtorcon/0.10.1>`_ (:download:`local-sig </../signatues/txtorcon-0.10.1.tar.gz.asc>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.10.1.tar.gz.asc?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.10.1.tar.gz>`_) 
 * fix bug incorrectly issuing RuntimeError in brief window of time on event-listeners
 * issue #78: Add tox tests and fix for Twisted 12.0.0 (and prior), as this is what Debian squeeze ships
 * issue #77: properly expand relative and tilde paths for ``hiddenServiceDir`` via endpoints


v0.10.0
-------

*June 15, 2014*

 * `txtorcon-0.10.0.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.10.0.tar.gz>`_ (`PyPI <https://pypi.python.org/pypi/txtorcon/0.10.0>`_ (:download:`local-sig </../signatues/txtorcon-0.10.0.tar.gz.asc>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.10.0.tar.gz.asc?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.10.0.tar.gz>`_)
 * In collaboration with `David Stainton <https://github.com/david415>`_ after a pull-request, we
   have endpoint parser plugins for Twisted! This means code like
   ``serverFromString("onion:80").listen(...)`` is enough to start a
   service. See the **4-line example** :ref:`hello_darkweb.py`
 * The above **also** means that **any** endpoint-using Twisted program can immediately offer its TCP services via Hidden Service with **no code changes**.    For example, using Twisted Web to serve a WSGI web application would be simply: ``twistd web --port onion:80 --wsgi web.app``
 * switch to a slightly-modified `Alabaster Sphinx theme <https://github.com/bitprophet/alabaster>`_
 * added :doc:`howtos` to documentation (see :ref:`howto-endpoint`, with demo "video")


v0.9.2
------

*April 23, 2014*

 * `txtorcon-0.9.2.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.9.2.tar.gz>`_ (:download:`local-sig </../signatues/txtorcon-0.9.2.tar.gz.asc>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.9.2.tar.gz.asc?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.9.2.tar.gz>`_)
 * add ``on_disconnect`` callback for TorControlProtocol (no more monkey-patching Protocol API)
 * add ``age()`` method to Circuit
 * add ``time_created`` property to Circuit
 * don't incorrectly listen for NEWDESC events in TorState
 * add ``.flags`` dict to track flags in Circuit, Stream
 * ``build_circuit()`` can now take hex IDs (as well as Router instances)
 * add ``unique_name`` property to Router (returns the hex id, unless ``Named`` then return name)
 * add ``location`` property to Router
 * ``TorState.close_circuit`` now takes either a Circuit ID or Circuit instance
 * ``TorState.close_stream`` now takes either a Stream ID or Stream instance
 * support both GeoIP API versions
 * more test-coverage
 * small patch from `enriquefynn <https://github.com/enriquefynn>`_ improving ``tor`` binary locating
 * strip OK lines in TorControlProtocol (see `issue #8 <https://github.com/meejah/txtorcon/issues/8>`_)
 * use TERM not KILL when Tor launch times out (see `issue #68 <https://github.com/meejah/txtorcon/pull/68>`_) from ``hellais``


v0.9.1
------

*January 20, 2014*

 * `txtorcon-0.9.1.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.9.1.tar.gz>`_ (:download:`local-sig </../signatues/txtorcon-0.9.1.tar.gz.asc>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.9.1.tar.gz.asc?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.9.1.tar.gz>`_)
 * put test/ directory at the top level
 * using "`coverage <http://nedbatchelder.com/code/coverage/>`_" tool instead of custom script
 * using `coveralls.io <https://coveralls.io/r/meejah/txtorcon>`_ and `travis-ci <https://travis-ci.org/meejah/txtorcon>`_ for test coverage and continuous integration
 * `issue #56 <https://github.com/meejah/txtorcon/issues/56>`_: added Circuit.close() and Stream.close() starting from aagbsn's patch
 * parsing issues with multi-line keyword discovered and resolved
 * preserve router nicks from long-names if consensus lacks an entry (e.g. bridges)
 * using `Twine <https://github.com/dstufft/twine>`_ for releases
 * `Wheel <http://wheel.readthedocs.org/en/latest/>`_ release now also available
 * `issue #57 <https://github.com/meejah/txtorcon/issues/57>`_: "python setup.py develop" now supported
 * `issue #59 <https://github.com/meejah/txtorcon/pull/59>`_: if tor_launch() times out, Tor is properly killed (starting with pull-request from Ryman)
 * experimental docker.io-based tests (for HS listening, and tor_launch() timeouts)
 * `issue #55 <https://github.com/meejah/txtorcon/issues/55>`_: pubkey link on readthedocs
 * `issue #63 <https://github.com/meejah/txtorcon/issues/55>`_
 * clean up GeoIP handling, and support pygeoip both pre and post 0.3
 * slightly improve unit-test coverage (now at 97%, 61 lines of 2031 missing)
 * added a `Walkthrough <walkthrough.html>`_ to the documentation


v0.8.2
------

*November 22, 2013*

 * `txtorcon-0.8.2.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.8.2.tar.gz>`_ (:download:`local-sig </../signatues/txtorcon-0.8.2.tar.gz.asc>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.8.2.tar.gz.asc?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.8.2.tar.gz>`_)
 * ensure hidden service server-side endpoints listen only on 127.0.0.1


v0.8.1
------

*May 13, 2013*

 * `txtorcon-0.8.1.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.8.1.tar.gz>`_ (:download:`local-sign </../signatues/txtorcon-0.8.1.tar.gz.sig>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.8.1.tar.gz.sig?raw=true>`_) (`source <https://github.com/meejah/txtorcon/archive/v0.8.1.tar.gz>`_)
 * fixed improper import in setup.py preventing 0.8.0 from installing
 * signatures with proper subkey this time
 * Proper file-flushing in tests and PyPy fixes from Lukas Lueg
 * docs build issue from isis

v0.8.0
------

*April 11, 2013* (actually uploaded May 11)

 * **Please use 0.8.1; this won't install due to import problem in setup.py (unless you have pypissh).**
 * following `semantic versioning <http://semver.org/>`_;
 * slight **API change** :meth:`.ICircuitListener.circuit_failed`, :meth:`~.ICircuitListener.circuit_closed` and :meth:`.IStreamListener.stream_failed`, :meth:`~.IStreamListener.stream_closed` and :meth:`~.IStreamListener.stream_detach` all now include any keywords in the notification method (some of these lacked flags, or only included some) (`issue #18 <https://github.com/meejah/txtorcon/issues/18>`_);
 * launch_tor() can take a timeout (starting with a patch from hellais);
 * cleanup from aagbsn;
 * more test coverage;
 * run tests cleanly without graphviz (from lukaslueg);
 * `issue #26 <https://github.com/meejah/txtorcon/issues/26>`_ fix from lukaslueg;
 * pep8 and whitespace targets plus massive cleanup (now pep8 clean, from lukaslueg);
 * `issue #30 <https://github.com/meejah/txtorcon/issues/30>`_ fix reported by webmeister making ipaddr actually-optional;
 * example using synchronous web server (built-in SimpleHTTPServer) with txtorcon (from lukaslueg);
 * TorState can now create circuits without an explicit path;
 * passwords for non-cookie authenticated sessions use a password callback (that may return a Deferred) instead of a string (`issue #44 <https://github.com/meejah/txtorcon/issues/44>`_);
 * fixes for AddrMap in case `#8596 <https://trac.torproject.org/projects/tor/ticket/8596>`_ is implemented;

v0.7
----

*November 21, 2012*

 * `txtorcon-0.7.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.7.tar.gz>`_ (:download:`local-sig <../signatues/txtorcon-0.7.tar.gz.sig>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.7.tar.gz.sig?raw=true>`_) (`source <https://github.com/meejah/txtorcon/tarball/v0.7>`_)
 * `issue #20 <https://github.com/meejah/txtorcon/issues/20>`_ config object now hooked up correctly after launch_tor();
 * `patch <https://github.com/meejah/txtorcon/pull/22>`_ from hellais for properly handling data_dir given to TCPHiddenServiceEndpoint;
 * `.tac example <https://github.com/meejah/txtorcon/pull/19>`_ from mmaker;
 * allow TorConfig().hiddenservices.append(hs) to work properly with no attached protocol

v0.6
----

*October 10, 2012*

 * `txtorcon-0.6.tar.gz <http://timaq4ygg2iegci7.onion/txtorcon-0.6.tar.gz>`_ (:download:`local-sig <../signatues/txtorcon-0.6.tar.gz.sig>` or `github-sig <https://github.com/meejah/txtorcon/blob/master/signatues/txtorcon-0.6.tar.gz.sig?raw=true>`_) (`source <https://github.com/meejah/txtorcon/tarball/v0.6>`_)
 * debian packaging (mmaker);
 * psutil fully gone;
 * *changed API* for launch_tor() to use TorConfig instead of args;
 * TorConfig.save() works properly with no connected Tor;
 * fix incorrect handling of 650 immediately after connect;
 * `pep8 compliance <http://www.python.org/dev/peps/pep-0008/>`_;
 * use assertEqual in tests;
 * messages with embdedded keywords work properly;
 * fix bug with setup.py + pip;
 * `issue #15 <https://github.com/meejah/txtorcon/issues/15>`_ reported along with patch by `Isis Lovecruft <https://github.com/isislovecruft>`_;
 * consolidate requirements (from `aagbsn <https://github.com/aagbsn>`_);
 * increased test coverage and various minor fixes;
 * https URIs for ReadTheDocs;

v0.5
----
June 20, 2012

 * `txtorcon-0.5.tar.gz <txtorcon-0.5.tar.gz>`_ (`txtorcon-0.5.tar.gz.sig <txtorcon-0.5.tar.gz.sig>`_) (`source <https://github.com/meejah/txtorcon/tarball/v0.5>`_)
 * remove psutil as a dependency, including from `util.process_from_address`

v0.4
----
June 6, 2012

 * `txtorcon-0.4.tar.gz <txtorcon-0.4.tar.gz>`_ (`txtorcon-0.4.tar.gz.sig <txtorcon-0.4.tar.gz.sig>`_)
 * remove built documentation from distribution; 
 * fix PyPI problems ("pip install txtorcon" now works)

v0.3
----
 * 0.3 was broken when released (docs couldn't build).

v0.2
----
June 1, 2012

 * `txtorcon-0.2.tar.gz <txtorcon-0.2.tar.gz>`_ (`txtorcon-0.2.tar.gz.sig <txtorcon-0.2.tar.gz.sig>`_)
 * incremental parsing;
 * faster TorState startup;
 * SAFECOOKIE support;
 * several bug fixes;
 * options to :ref:`circuit_failure_rates.py` example to make it actually-useful;
 * include built documentation + sources in tarball;
 * include tests in tarball;
 * improved logging;
 * patches from `mmaker <https://github.com/mmaker>`_ and `kneufeld <https://github.com/kneufeld>`_;

v0.1
----
march, 2012

 * `txtorcon-0.1.tar.gz <txtorcon-0.1.tar.gz>`_ (`txtorcon-0.1.tar.gz.sig <txtorcon-0.1.tar.gz.sig>`_)

