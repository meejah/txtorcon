.. txtorcon documentation master file, created by
   sphinx-quickstart on Thu Jan 26 13:04:28 2012.

txtorcon
========

- **docs**:
   - v3 onion: http://fjblvrw2jrxnhtg67qpbzi45r7ofojaoo3orzykesly2j3c2m3htapid.onion/
   - clearnet: https://txtorcon.readthedocs.org
- **code**: https://github.com/meejah/txtorcon
- ``torsocks git clone git://fjblvrw2jrxnhtg67qpbzi45r7ofojaoo3orzykesly2j3c2m3htapid.onion/txtorcon.git``

- .. image:: https://github.com/meejah/txtorcon/actions/workflows/python3.yaml/badge.svg
    :target: https://github.com/meejah/txtorcon/actions
    :alt: github-actions

  .. image:: https://coveralls.io/repos/meejah/txtorcon/badge.svg
      :target: https://coveralls.io/r/meejah/txtorcon

  .. image:: https://readthedocs.org/projects/txtorcon/badge/?version=stable
      :target: https://txtorcon.readthedocs.io/en/stable
      :alt: ReadTheDocs

  .. image:: https://readthedocs.org/projects/txtorcon/badge/?version=latest
      :target: https://txtorcon.readthedocs.io/en/latest
      :alt: ReadTheDocs

.. container:: first_time

    If this is your first time exploring txtorcon, please **look at the**
    :ref:`introduction` **first**. These docs are for version |version|.

.. comment::

    +---------------+---------+---------+
    |   Twisted     | 15.5.0+ | 16.3.0+ |
    +===============+=========+=========+
    |   Python 2.7+ |    ✓    |    ✓    |
    +---------------+---------+---------+
    |   Python 3.5+ |    ✓    |    ✓    |
    +---------------+---------+---------+
    |   PyPy 5.0.0+ |    ✓    |    ✓    |
    +---------------+---------+---------+

Supported and tested platforms: Python 3.5+, PyPy 5.0.0+, Python 2.7+ (deprecated)
using Twisted 15.5.0+, 16.3.0+, or 17.1.0+ (see `GitHub Actions
<https://github.com/meejah/txtorcon/actions>`_).

**Asycnio inter-operation** is now possible, see :ref:`interop_asyncio`


Documentation
-------------

.. toctree::
   :maxdepth: 3

   introduction
   installing
   guide
   examples
   interop_asyncio
   hacking


Official Releases:
------------------

All official releases are tagged in Git, and signed by my key. All official releases on PyPI have a corresponding GPG signature of the build. Please be aware that ``pip`` does *not* check GPG signatures by default; please see `this ticket <https://github.com/pypa/pip/issues/1035>`_ if you care.

The most reliable way to verify you got what I intended is to clone the Git repository, ``git checkout`` a tag and verify its signature. The second-best would be to download a release + tag from PyPI and verify that.


.. toctree::
   :maxdepth: 2

   releases


API Documentation
-----------------

These are the lowest-level documents, directly from the doc-strings in
the code with some minimal organization; if you're just getting
started with txtorcon **the** ":ref:`programming_guide`" **is a better
place to start**.

.. toctree::
   :maxdepth: 3

   txtorcon


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

