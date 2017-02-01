# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function
from __future__ import with_statement

from twisted.web.iweb import IAgentEndpointFactory
from twisted.web.client import Agent
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.endpoints import TCP4ClientEndpoint, UNIXClientEndpoint

from zope.interface import implementer

from txtorcon.socks import TorSocksEndpoint
from txtorcon.log import txtorlog


@implementer(IAgentEndpointFactory)
class _AgentEndpointFactoryUsingTor(object):
    def __init__(self, reactor, tor_socks_endpoint):
        self._reactor = reactor
        self._proxy_ep = tor_socks_endpoint
        # XXX could accept optional "tls=" to do something besides
        # optionsForClientTLS(hostname)?

    def endpointForURI(self, uri):
        return TorSocksEndpoint(
            self._proxy_ep,
            uri.host,
            uri.port,
            tls=(uri.scheme == b'https'),
        )


# note to self: put circuit-specific agent back in after, and add
# "circuit=" kwarg too


def tor_agent(reactor, socks_endpoint, pool=None):
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

    :param torconfig: a :class:`txtorcon.TorConfig` instance

    :param socks_endpoint: Deferred that fires w/
        IStreamClientEndpoint (or IStreamClientEndpoint instance)

    :param pool: passed on to the Agent (as ``pool=``)
    """

    factory = _AgentEndpointFactoryUsingTor(reactor, socks_endpoint)
    return Agent.usingEndpointFactory(reactor, factory, pool=pool)


@inlineCallbacks
def agent_for_socks_port(reactor, torconfig, socks_config, pool=None):
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
    """
    # :param tls: True (the default) will use Twisted's default options
    #     with the hostname in the URI -- that is, TLS verification
    #     similar to a Browser. Otherwise, you can pass whatever Twisted
    #     returns for `optionsForClientTLS
    #     <https://twistedmatrix.com/documents/current/api/twisted.internet.ssl.optionsForClientTLS.html>`_

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

    returnValue(
        Agent.usingEndpointFactory(
            reactor,
            _AgentEndpointFactoryUsingTor(reactor, socks_ep),
            pool=pool,
        )
    )
