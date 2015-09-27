# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import with_statement

# for now, this needs to be changed in setup.py also until I find a
# better solution
__version__ = '0.14.0'
__author__ = 'meejah'
__contact__ = 'meejah@meejah.ca'
__url__ = 'https://github.com/meejah/txtorcon'
__license__ = 'MIT'
__copyright__ = 'Copyright 2012-2015'


from txtorcon.router import Router
from txtorcon.circuit import Circuit
from txtorcon.stream import Stream
from txtorcon.torcontrolprotocol import TorControlProtocol
from txtorcon.torcontrolprotocol import TorProtocolError
from txtorcon.torcontrolprotocol import TorProtocolFactory
from txtorcon.torcontrolprotocol import DEFAULT_VALUE
from txtorcon.torstate import TorState
from txtorcon.torstate import build_tor_connection
from txtorcon.torstate import build_local_tor_connection
from txtorcon.torconfig import TorConfig
from txtorcon.torconfig import HiddenService
from txtorcon.torconfig import TorProcessProtocol
from txtorcon.torconfig import launch_tor
from txtorcon.torconfig import TorNotFound
from txtorcon.torinfo import TorInfo
from txtorcon.addrmap import AddrMap
from txtorcon.endpoints import TorOnionAddress
from txtorcon.endpoints import TorOnionListeningPort
from txtorcon.endpoints import TCPHiddenServiceEndpoint
from txtorcon.endpoints import TCPHiddenServiceEndpointParser
from txtorcon.endpoints import TorClientEndpoint
from txtorcon.endpoints import TorClientEndpointStringParser
from txtorcon.endpoints import IHiddenService
from txtorcon.endpoints import IProgressProvider
from txtorcon.endpoints import get_global_tor
from . import util
from . import interface
from txtorcon.interface import *

__all__ = ["Router",
           "Circuit",
           "Stream",
           "TorControlProtocol", "TorProtocolError", "TorProtocolFactory",
           "TorState", "DEFAULT_VALUE",
           "TorInfo",
           "build_tor_connection", "build_local_tor_connection", "launch_tor",
           "TorNotFound", "TorConfig", "HiddenService", "TorProcessProtocol",
           "TorInfo",
           "TCPHiddenServiceEndpoint", "TCPHiddenServiceEndpointParser",
           "TorClientEndpoint", "TorClientEndpointStringParser",
           "IHiddenService", "IProgressProvider",
           "TorOnionAddress", "TorOnionListeningPort",
           "get_global_tor",

           "AddrMap",
           "util", "interface",
           "ITorControlProtocol",
           "IStreamListener", "IStreamAttacher", "StreamListenerMixin",
           "ICircuitContainer", "ICircuitListener", "CircuitListenerMixin",
           "IRouterContainer", "IAddrListener", "IProgressProvider",
           "IHiddenService",
           ]
