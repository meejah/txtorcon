# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function

try:
    import pypissh
except:
    print("WARNING: not using PyPi over SSH!")
import sys
import os
import shutil
import re
from setuptools import setup

# can't just naively import these from txtorcon, as that will only
# work if you already installed the dependencies :(
__version__ = '0.14.0'
__author__ = 'meejah'
__contact__ = 'meejah@meejah.ca'
__url__ = 'https://github.com/meejah/txtorcon'
__license__ = 'MIT'
__copyright__ = 'Copyright 2012-2015'


setup(name = 'txtorcon',
      version = __version__,
      description = 'Twisted-based Tor controller client, with state-tracking and configuration abstractions.',
      long_description = open('README.rst', 'r').read(),
      keywords = ['python', 'twisted', 'tor', 'tor controller'],
      install_requires = open('requirements.txt').readlines(),
      # "pip install -e .[dev]" will install development requirements
      extras_require=dict(
          dev=open('dev-requirements.txt').readlines(),
      ),
      classifiers = ['Framework :: Twisted',
                     'Development Status :: 4 - Beta',
                     'Intended Audience :: Developers',
                     'License :: OSI Approved :: MIT License',
                     'Natural Language :: English',
                     'Operating System :: POSIX :: Linux',
                     'Operating System :: Unix',
                     'Programming Language :: Python',
                     'Programming Language :: Python :: 2',
                     'Programming Language :: Python :: 2.6',
                     'Programming Language :: Python :: 2.7',
                     'Topic :: Software Development :: Libraries :: Python Modules',
                     'Topic :: Internet :: Proxy Servers',
                     'Topic :: Internet',
                     'Topic :: Security'],
      author = __author__,
      author_email = __contact__,
      url = __url__,
      license = __license__,
      packages  = ["txtorcon", "twisted.plugins"],
#      scripts = ['examples/attach_streams_by_country.py'],

      ## I'm a little unclear if I'm doing this "properly", especially
      ## the documentation etc. Do we really want "share/txtorcon" for
      ## the first member of the tuple? Why does it seem I need to
      ## duplicate this in MANIFEST.in?

      data_files = [('share/txtorcon', ['INSTALL', 'README.rst', 'TODO', 'meejah.asc']),

                    ## this includes the Sphinx source for the
                    ## docs. The "map+filter" construct grabs all .rst
                    ## files and re-maps the path
                    ('share/txtorcon', ['docs/apilinks_sphinxext.py', 'docs/conf.py', 'docs/Makefile'] + [os.path.join('docs', x) for x in [x for x in os.listdir('docs') if x[-3:] == 'rst']] + [os.path.join('docs/_static', x) for x in os.listdir('docs/_static')]),

                    ## include all the examples
                    ('share/txtorcon/examples', [os.path.join('examples', x) for x in [x for x in os.listdir('examples') if x[-3:] == '.py']])
                    ]
      )
