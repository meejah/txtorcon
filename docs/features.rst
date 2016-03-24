features and motivation
-----------------------

With txtorcon installed, you can use ``"onion:"`` port/endpoint
strings with **any endpoint-aware Twisted program**. For example, to use
Twisted Web to serve your ``~/public_html`` as a hidden service
(``-n`` *means don't daemonize and log to stdout*):

.. code-block:: shell-session

    $ twistd -n web --port "onion:80" --path ~/public_html
    2014-05-30 21:40:23-0600 [-] Log opened.
    #...truncated
    2014-05-30 21:41:16-0600 [TorControlProtocol,client] Tor launching: 90% Establishing a Tor circuit
    2014-05-30 21:41:17-0600 [TorControlProtocol,client] Tor launching: 100% Done
    2014-05-30 21:41:17-0600 [TorControlProtocol,client] Site starting on 46197
    2014-05-30 21:41:17-0600 [TorControlProtocol,client] Starting factory <twisted.web.server.Site instance at 0x7f57667d0cb0>
    2014-05-30 21:41:17-0600 [TorControlProtocol,client] Set up hidden service "2vrrgqtpiaildmsm.onion" on port 80

There's a `complete demonstration <https://asciinema.org/a/10145>`_ at asciinema.org.

Some (other) features and motivating examples:

 - :class:`txtorcon.TorControlProtocol` implements the control-spec protocol (only)
    - see :ref:`monitor.py` which listens for events (SETEVENT ones)

 - :class:`txtorcon.TorState` tracks state for you: all Routers, Streams and Circuits, with listeners
    - see :ref:`stream_circuit_logger.py` which logs all stream and circuit activity

 - :class:`txtorcon.TorConfig` tracks and allows updating of config with attribute-style acccess (including hidden services):
    - :samp:`print config.ORPort`
    - :samp:`config.HiddenServices.append(HiddenService(config, '/hidden/service/dir', ['80 127.0.0.1:1234']))`
    - :samp:`config.SocksPort = 9052`
    - see :ref:`dump_config.py`
    - see also :ref:`launch_tor_with_hiddenservice.py`

 - helpers to launch new slave Tor instances
    - use :class:`txtorcon.TCPHiddenServiceEndpoint` and :api:`twisted.internet.endpoints.serverFromString <serverFromString>` if you can
    - uses TAKEOWNERSHIP and __OwningControllerProcess (killing connection causes Tor to exit)
    - see :ref:`launch_tor.py`
    - see :ref:`launch_tor_with_hiddenservice.py`

 - :class:`txtorcon.TCPHiddenServiceEndpoint` to simplify hidden service listening into Twisteds endpoint paradigm.
    - see :ref:`launch_tor_endpoint.py`


A slight change to the Echo Server example on the front page of
`Twisted's Web site <https://twistedmatrix.com/trac>`_ can make it
appear as a hidden service:

.. code-block:: python

    from __future__ import print_function
    from twisted.internet import protocol, reactor, endpoints

    class Echo(protocol.Protocol):
        def dataReceived(self, data):
            self.transport.write(data)

    class EchoFactory(protocol.Factory):
        def buildProtocol(self, addr):
            return Echo()

    endpoints.serverFromString(reactor, "onion:1234").listen(EchoFactory()).addCallback(lambda x: print(x.getHost()))
    reactor.run()

This is just a one-line change. Note there isn't even an "import
txtorcon" (although it does need to be installed so that Twisted finds
the ``IPlugin`` that does the parsing).


