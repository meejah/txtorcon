## for now, this needs to be changed in setup.py also until I find a
## better solution
__version__ = '0.7'
__author__ = 'meejah'
__contact__ = 'meejah@meejah.ca'
__url__ = 'https://github.com/meejah/txtorcon'
__license__ = 'MIT'
__copyright__ = 'Copyright 2012'

import glob
import os
import subprocess


def check_tor_binary(path):
    return os.path.isfile(path) and os.access(path, os.X_OK)


def find_tor_binary(globs=('/usr/sbin/', '/usr/bin/',
                           '/Applications/TorBrowser_*.app/Contents/MacOS/')):
    # Try to find the tor executable using the shell
    try:
        proc = subprocess.Popen(('type -p tor', ), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=True)
    except OSError:
        pass
    else:
        out, _ = proc.communicate()
        if proc.poll() == 0 and out != '':
            return out.strip()
    # the shell may not provide type and tor is usually not on PATH when using
    # the browser-bundle. Look in specific places
    for pattern in globs:
        for path in glob.glob(pattern):
            bin = os.path.join(path, 'tor')
            if check_tor_binary(bin):
                return bin


from txtorcon.router import Router
from txtorcon.circuit import Circuit
from txtorcon.stream import Stream
from txtorcon.torcontrolprotocol import TorControlProtocol, TorProtocolError, TorProtocolFactory, DEFAULT_VALUE
from txtorcon.torstate import TorState, build_tor_connection
from txtorcon.torconfig import TorConfig, HiddenService, TorProcessProtocol, TCPHiddenServiceEndpoint, launch_tor
from txtorcon.torinfo import TorInfo
from txtorcon.addrmap import AddrMap
import util
import interface
from txtorcon.interface import *

__all__ = ["Router",
           "Circuit",
           "Stream",
           "TorControlProtocol", "TorProtocolError", "TorProtocolFactory",
           "TorState", "DEFAULT_VALUE",
           "TorInfo",
           "build_tor_connection", "launch_tor",
           "TorConfig", "HiddenService", "TorProcessProtocol",
           "TorInfo",
           "TCPHiddenServiceEndpoint",
           "AddrMap",
           "util", "interface",
           "ITorControlprotocol",
           "IStreamListener", "IStreamAttacher", "StreamListenerMixin",
           "ICircuitContainer", "ICircuitListener", "CircuitListenerMixin",
           "IRouterContainer", "IAddrListener"
           ]
