# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function

from os.path import join
from os import listdir
from setuptools import setup

# Hmmmph.
# So we get all the meta-information in one place (yay!) but we call
# exec to get it (boo!). Note that we can't "from txtorcon._metadata
# import *" here because that won't work when setup is being run by
# pip (outside of Git checkout etc)
with open('txtorcon/_metadata.py') as f:
    exec(
        compile(f.read(), '_metadata.py', 'exec'),
        globals(),
        locals(),
    )

description = '''
    Twisted-based Tor controller client, with state-tracking and
    configuration abstractions.
    https://txtorcon.readthedocs.org
    https://github.com/meejah/txtorcon
'''
# if there are any newlines in the short-description, there's no error
# .. but setuptools / pip / readme_renderere "or something" causes the
# 'descript' to be all the meta-data after 'summary', which fails to
# render.
# see: https://github.com/pypa/setuptools/issues/1390
description = description.replace('\n', ' ')

sphinx_rst_files = [x for x in listdir('docs') if x[-3:] == 'rst']
sphinx_docs = [join('docs', x) for x in sphinx_rst_files]
sphinx_docs += [join('docs/_static', x) for x in listdir('docs/_static')]
examples = [x for x in listdir('examples') if x[-3:] == '.py']

setup(
    name='txtorcon',
    version=__version__,
    description=description,
    setup_requires="setuptools>=36.2",
    long_description=open('README.rst', 'r').read(),
    keywords=['python', 'twisted', 'tor', 'tor controller'],
    install_requires=open('requirements.txt').readlines(),
    # "pip install -e .[dev]" will install development requirements
    extras_require=dict(
        dev=open('dev-requirements.txt').readlines(),
    ),
    classifiers=[
        'Framework :: Twisted',
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
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Internet :: Proxy Servers',
        'Topic :: Internet',
        'Topic :: Security',
    ],
    author=__author__,
    author_email=__contact__,
    url=__url__,
    license=__license__,
    packages=[
        "txtorcon",
        "twisted.plugins",
    ],

    # I'm a little unclear if I'm doing this "properly", especially
    # the documentation etc. Do we really want "share/txtorcon" for
    # the first member of the tuple? Why does it seem I need to
    # duplicate this in MANIFEST.in?

    data_files=[
        ('share/txtorcon', ['INSTALL', 'README.rst', 'TODO', 'meejah.asc']),

        # this includes the Sphinx source for the
        # docs. The "map+filter" construct grabs all .rst
        # files and re-maps the path
        ('share/txtorcon', [
            'docs/apilinks_sphinxext.py',
            'docs/conf.py',
            'docs/Makefile',
        ] + sphinx_docs),

        # include all the examples
        ('share/txtorcon/examples', [join('examples', x) for x in examples])
    ],
)
