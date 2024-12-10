# -*- coding: utf-8 -*-

from twisted.web.iweb import IAgentEndpointFactory
from twisted.web.client import Agent, BrowserLikePolicyForHTTPS
from twisted.internet.defer import inlineCallbacks, Deferred
from twisted.internet.endpoints import TCP4ClientEndpoint, UNIXClientEndpoint

from zope.interface import implementer

from txtorcon.socks import TorSocksEndpoint
from txtorcon.log import txtorlog
from txtorcon.util import SingleObserver


@implementer(IAgentEndpointFactory)
class _AgentEndpointFactoryUsingTor:
    def __init__(self, reactor, tor_socks_endpoint, tls_context_factory):
        self._reactor = reactor
        self._proxy_ep = SingleObserver()
        # if _proxy_ep is Deferred, but we get called twice, we must
        # remember the resolved object here
        if isinstance(tor_socks_endpoint, Deferred):
            tor_socks_endpoint.addCallback(self._set_proxy)
        else:
            self._proxy_ep.fire(tor_socks_endpoint)

        if tls_context_factory is None:
            tls_context_factory = BrowserLikePolicyForHTTPS()
        self._tls_context_factory = tls_context_factory

    def _set_proxy(self, p):
        self._proxy_ep.fire(p)
        return p

    def endpointForURI(self, uri):
        if uri.scheme == b'https':
            tls = self._tls_context_factory.creatorForNetloc(uri.host, uri.port)
        else:
            tls = False
        return TorSocksEndpoint(
            self._proxy_ep.when_fired(),
            uri.host,
            uri.port,
            tls=tls,
        )


@implementer(IAgentEndpointFactory)
class _AgentEndpointFactoryForCircuit(object):
    def __init__(self, reactor, tor_socks_endpoint, circ, tls_context_factory):
        self._reactor = reactor
        self._socks_ep = tor_socks_endpoint
        self._circ = circ
        if tls_context_factory is None:
            tls_context_factory = BrowserLikePolicyForHTTPS()
        self._tls_context_factory = tls_context_factory

    def endpointForURI(self, uri):
        """IAgentEndpointFactory API"""
        if uri.scheme == b'https':
            tls = self._tls_context_factory.creatorForNetloc(uri.host, uri.port)
        else:
            tls = False
        torsocks = TorSocksEndpoint(
            self._socks_ep,
            uri.host, uri.port,
            tls=tls,
        )
        from txtorcon.circuit import TorCircuitEndpoint
        return TorCircuitEndpoint(
            self._reactor, self._circ._torstate, self._circ, torsocks,
        )


def tor_agent(reactor, socks_endpoint, circuit=None, pool=None, tls_context_factory=None):
    """
    This is the low-level method used by
    :meth:`txtorcon.Tor.web_agent` and
    :meth:`txtorcon.Circuit.web_agent` -- probably you should call one
    of those instead.

    :returns: a Deferred that fires with an object that implements
        :class:`twisted.web.iweb.IAgent` and is thus suitable for passing
        to ``treq`` as the ``agent=`` kwarg. Of course can be used
        directly; see `using Twisted web cliet
        <http://twistedmatrix.com/documents/current/web/howto/client.html>`_.

    :param reactor: the reactor to use

    :param circuit: If supplied, a particular circuit to use

    :param socks_endpoint: Deferred that fires w/
        IStreamClientEndpoint (or IStreamClientEndpoint instance)
        which points at a SOCKS5 port of our Tor

    :param pool: passed on to the Agent (as ``pool=``)

    :param tls_context_factory: A factory for TLS contexts. If ``None``,
        ``BrowserLikePolicyForHTTPS`` is used.
    """
    if socks_endpoint is None:
        raise ValueError(
            "Must provide socks_endpoint as Deferred or IStreamClientEndpoint"
        )
    if circuit is not None:
        factory = _AgentEndpointFactoryForCircuit(
            reactor, socks_endpoint, circuit, tls_context_factory
        )
    else:
        factory = _AgentEndpointFactoryUsingTor(
            reactor, socks_endpoint, tls_context_factory
        )

    return Agent.usingEndpointFactory(reactor, factory, pool=pool)


@inlineCallbacks
def agent_for_socks_port(reactor, torconfig, socks_config, pool=None,
                         tls_context_factory=None):
    """
    This returns a Deferred that fires with an object that implements
    :class:`twisted.web.iweb.IAgent` and is thus suitable for passing
    to ``treq`` as the ``agent=`` kwarg. Of course can be used
    directly; see `using Twisted web cliet
    <http://twistedmatrix.com/documents/current/web/howto/client.html>`_. If
    you have a :class:`txtorcon.Tor` instance already, the preferred
    API is to call :meth:`txtorcon.Tor.web_agent` on it.

    :param torconfig: a :class:`txtorcon.TorConfig` instance.

    :param socks_config: anything valid for Tor's ``SocksPort``
        option. This is generally just a TCP port (e.g. ``9050``), but
        can also be a unix path like so ``unix:/path/to/socket`` (Tor
        has restrictions on the ownership/permissions of the directory
        containing ``socket``). If the given SOCKS option is not
        already available in the underlying Tor instance, it is
        re-configured to add the SOCKS option.

    :param tls_context_factory: A factory for TLS contexts. If ``None``,
        ``BrowserLikePolicyForHTTPS`` is used.
    """
    socks_config = str(socks_config)  # sadly, all lists are lists-of-strings to Tor :/
    if socks_config not in torconfig.SocksPort:
        txtorlog.msg("Adding SOCKS port '{}' to Tor".format(socks_config))
        torconfig.SocksPort.append(socks_config)
        try:
            yield torconfig.save()
        except Exception as e:
            raise RuntimeError(
                "Failed to reconfigure Tor with SOCKS port '{}': {}".format(
                    socks_config, str(e)
                )
            )

    if socks_config.startswith('unix:'):
        socks_ep = UNIXClientEndpoint(reactor, socks_config[5:])
    else:
        if ':' in socks_config:
            host, port = socks_config.split(':', 1)
        else:
            host = '127.0.0.1'
            port = int(socks_config)
        socks_ep = TCP4ClientEndpoint(reactor, host, port)

    return Agent.usingEndpointFactory(
        reactor,
        _AgentEndpointFactoryUsingTor(
            reactor, socks_ep, tls_context_factory=tls_context_factory
        ),
        pool=pool,
    )
