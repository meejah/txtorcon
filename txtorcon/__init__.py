# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import with_statement

from txtorcon._metadata import __version__, __author__, __contact__
from txtorcon._metadata import __license__, __copyright__, __url__

from txtorcon.router import Router
from txtorcon.circuit import Circuit
from txtorcon.circuit import build_timeout_circuit
from txtorcon.circuit import CircuitBuildTimedOutError
from txtorcon.stream import Stream
from txtorcon.controller import connect
from txtorcon.controller import launch
from txtorcon.controller import Tor
from txtorcon.controller import TorProcessProtocol
from txtorcon.controller import TorNotFound
from txtorcon.torcontrolprotocol import TorControlProtocol
from txtorcon.torcontrolprotocol import TorProtocolError
from txtorcon.torcontrolprotocol import TorProtocolFactory
from txtorcon.torcontrolprotocol import DEFAULT_VALUE
from txtorcon.torstate import TorState
from txtorcon.torstate import build_tor_connection
from txtorcon.torstate import build_local_tor_connection
from txtorcon.torconfig import TorConfig
from txtorcon.onion import EphemeralHiddenService
from txtorcon.onion import FilesystemHiddenService
from txtorcon.onion import AuthenticatedHiddenService
# from txtorcon.onion import create_onion_service
# from txtorcon.onion import launch_tor # XXX backwards-compat: (put back??)
# from txtorcon.onion import IOnionService
# from txtorcon.onion import IAuthenticatedOnionService
# from txtorcon.onion import OnionService, EphemeralOnionService
from txtorcon.torinfo import TorInfo
from txtorcon.addrmap import AddrMap
from txtorcon.endpoints import TorOnionAddress
from txtorcon.endpoints import TorOnionListeningPort
from txtorcon.endpoints import TCPHiddenServiceEndpoint
from txtorcon.endpoints import TCPHiddenServiceEndpointParser
from txtorcon.endpoints import TorClientEndpoint
from txtorcon.endpoints import TorClientEndpointStringParser
from txtorcon.endpoints import IHiddenService, IProgressProvider

from txtorcon.endpoints import get_global_tor
from txtorcon.interface import (
    ITorControlProtocol,
    IStreamListener, IStreamAttacher, StreamListenerMixin,
    ICircuitContainer, ICircuitListener, CircuitListenerMixin,
    IRouterContainer, IAddrListener,
)

try:
    from txtorcon.web import agent_for_socks_port
except ImportError as e:
    def agent_for_socks_port(*args, **kw):
        raise RuntimeError("Couldn't import {}, so no web-agent available".format(e))


HiddenService = FilesystemHiddenService  # backwards-compat; plz deprecate!


__all__ = [
    "Router",
    "Circuit",
    "Stream",
    "connect", "launch", "Tor",
    "TorControlProtocol", "TorProtocolError", "TorProtocolFactory",
    "TorState", "DEFAULT_VALUE",
    "TorInfo",
    "build_tor_connection", "build_local_tor_connection",
    "launch_tor",  # XXX deprecate?
    "create_onion_service",
    "TorNotFound", "TorConfig",
    "EphemeralHiddenService", "FilesystemHiddenService", "HiddenService", "AuthenticatedHiddenService",  # XXX FIXME
    "TorProcessProtocol",
    "TorInfo",
    "TCPHiddenServiceEndpoint", "TCPHiddenServiceEndpointParser",
    "TorClientEndpoint", "TorClientEndpointStringParser",
    "IHiddenService", "IProgressProvider",
    "TorOnionAddress", "TorOnionListeningPort",
    "get_global_tor",
    "build_timeout_circuit",
    "CircuitBuildTimedOutError",
    "AddrMap",
    "ITorControlProtocol",
    "IStreamListener", "IStreamAttacher", "StreamListenerMixin",
    "ICircuitContainer", "ICircuitListener", "CircuitListenerMixin",
    "IRouterContainer", "IAddrListener", "IProgressProvider",
    "IHiddenService",

    # new onion + ephemeral API
    "IOnionService", "IAuthenticatedOnionService",
    "EphemeralOnionService",

    # web stuff
    "agent_for_socks_port",

    "__version__", "__author__", "__contact__",
    "__license__", "__copyright__", "__url__",
]
