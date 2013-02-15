Releases
========

There isn't a "release schedule" in any sense. If there is something
in master you depend on, let me know and I'll do a release. Starting
with v0.8.0 versions will follow `semantic versioning <http://semver.org/>`_.

unreleased
----------

`git master <https://github.com/meejah/txtorcon>`_ *will become v0.8.0*

 * (`source tgz <https://github.com/meejah/txtorcon/tarball/master>`_)
 * slight **API change** ICircuitListener.circuit_failed, circuit_closed and IStreamListener.stream_failed, stream_closed and stream_detach all now include any keywords in the notification method (some of these lacked flags, or only included some) (`issue #18 <https://github.com/meejah/txtorcon/issues/18>`_);
 * launch_tor() can take a timeout (starting with a patch from hellais);
 * cleanup from aagbsn;
 * more test coverage;
 * run tests cleanly without graphviz (from lukaslueg);
 * `issue #26 <https://github.com/meejah/txtorcon/issues/26>`_ fix from lukaslueg;
 * pep8 and whitespace targets plus massive cleanup (now pep8 clean, from lukaslueg);
 * `issue #30 <https://github.com/meejah/txtorcon/issues/30>`_ fix reported by webmesiter making ipaddr actually-optional;
 * example using synchronous web server (built-in SimpleHTTPServer) with txtorcon (from lukaslueg);
 * TorState can now create circuits without an explicit path
 * passwords for non-cookie authenticated sessions use a password callback (that may return a Deferred) instead of a string (`issue #44 <https://github.com/meejah/txtorcon/issues/44>`_)

v0.7
----

*November 21, 2012*

 * `txtorcon-0.7.tar.gz <https://timaq4ygg2iegci7.onion/txtorcon-0.7.tar.gz>`_ (`txtorcon-0.7.tar.gz.sig <https://timaq4ygg2iegci7.onion/txtorcon-0.7.tar.gz.sig>`_) (`source <https://github.com/meejah/txtorcon/tarball/v0.7>`_)
 * `issue #20 <https://github.com/meejah/txtorcon/issues/20>`_ config object now hooked up correctly after launch_tor();
 * `patch <https://github.com/meejah/txtorcon/pull/22>`_ from hellais for properly handling data_dir given to TCPHiddenServiceEndpoint;
 * `.tac example <https://github.com/meejah/txtorcon/pull/19>`_ from mmaker;
 * allow TorConfig().hiddenservices.append(hs) to work properly with no attached protocol

v0.6
----

*October 10, 2012*

 * `txtorcon-0.6.tar.gz <https://timaq4ygg2iegci7.onion/txtorcon-0.6.tar.gz>`_ (`txtorcon-0.6.tar.gz.sig <https://timaq4ygg2iegci7.onion/txtorcon-0.6.tar.gz.sig>`_) (`source <https://github.com/meejah/txtorcon/tarball/v0.6>`_)
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

