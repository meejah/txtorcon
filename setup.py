import sys
import os
import shutil
from distutils.core import setup, Extension

from txtorcon import __version__, __author__, __contact__, __copyright__, __license__, __url__

setup(name = 'txtorcon',
      version = __version__,
      description = 'Twisted-based Tor controller client, with state-tracking and configuration abstractions.',
      long_description = open('README','r').read(),
      keywords = ['python', 'twisted', 'tor', 'tor controller'],
      requires = ['twisted (>10.1.0)',
                  'GeoIP',
                  'ipaddr'],
      classifiers = ['Framework :: Twisted',
                     'License :: OSI Approved :: GNU General Public License (GPL)',
                     'Natural Language :: English',
                     'Operating System :: POSIX :: Linux',
                     'Operating System :: Unix',
                     'Programming Language :: Python',
                     'Topic :: Internet :: Proxy Servers',
                     'Topic :: Internet',
                     'Topic :: Security'],                     
      author = __author__,
      author_email = __contact__,
      url = __url__,
      license = __license__,
      packages  = ["txtorcon"],
#      scripts = ['examples/attach_streams_by_country.py'],

      ## I'm a little unclear if I'm doing this "properly", especially
      ## the documentation etc.
      
      data_files = [('share/txtorcon', ['README', 'TODO']),
                    ('share/txtorcon', ['doc_html/index.html', 'doc_html/objects.inv'] + map(lambda x: os.path.join('doc_html/_static', x), os.listdir('doc_html/_static'))),
                    ('share/txtorcon/examples', map(lambda x: os.path.join('examples', x), filter(lambda x: x[-3:] == '.py', os.listdir('examples'))))
                    ]
      )
