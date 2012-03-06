from zope.interface import implements, Interface

class IStreamListener(Interface):
    """
    Notifications about changes to a :class:`txtorcon.Stream`.

    If you wish for your listener to be added to *all* new streams,
    see :meth:`txtorcon.TorState.add_stream_listener`.
    """
    
    def stream_new(self, stream):
        "a new stream has been created"
    
    def stream_succeeded(self, stream):
        "stream has succeeded"
    
    def stream_attach(self, stream, circuit):
        "the stream has been attached to a circuit"

    def stream_detach(self, stream, reason):
        "the stream has been detached from its circuit"

    def stream_closed(self, stream):
        "stream has been closed (won't be in controller's list anymore)"

    def stream_failed(self, stream, reason, remote_reason):
        "stream failed for some reason (won't be in controller's list anymore)"

class IStreamAttacher(Interface):
    """
    Used by :class:`txtorcon.TorState` to map streams to circuits (see
    :meth:`txtorcon.TorState.set_attacher`).

    Each time a new :class:`txtorcon.Stream` is created, this
    interface will be queried to find out which
    :class:`txtorcon.Circuit` it should be attached to.
    """

    def attach_stream(self, stream, circuits):
        """
        :param stream: The stream to attach, which will be in NEW state.

        :param circuits: all currently available :class:`txtorcon.Circuit`
            objects in the :class:`txtorcon.TorState` in a dict indexed by id. Note
            they are not limited to BUILT circuits.

        You should return a :class:`txtorcon.Circuit` instance which
        should be at state BUILT in the currently running Tor. You may
        also return a Deferred which will callback with the desired
        circuit. In this case, you will probably need to be aware that
        the callback from :meth:`txtorcon.TorState.build_circuit` does NOT call back
        with a Circuit (just Tor's response of 'EXTEND 1234') and any
        circuit you do return must be in the BUILT state anyway (which
        the above will not).

        See :ref:`attach_streams_by_country.py` for a complete
        example of using a Deferred in an IStreamAttacher.

        Alternatively, you may return None in which case the Tor
        controller will be told to choose a circuit itself.

        Note that Tor will refuse to attach to any circuit not in
        BUILT state; see ATTACHSTREAM in control-spec.txt

        Note also that you will not get a request to attach a stream
        that ends in .exit or .onion -- Tor won't let you specify how
        to attach .onion addresses anyway.
        """

class ICircuitContainer(Interface):
    """
    An interface that contains a bunch of Circuit objects and can look
    them up by id.
    """
    
    def find_circuit(self, id):
        ":return: a circuit for the id, or exception."

class ICircuitListener(Interface):
    """
    An interface to listen for updates to Circuits.
    """
    
    def circuit_new(self, circuit):
        """A new circuit has been created.  You'll always get one of
        these for every Circuit even if it doesn't go through the "launched"
        state."""
        
    def circuit_launched(self, circuit):
        "A new circuit has been started."

    def circuit_extend(self, circuit, router):
        "A circuit has been extended to include a new router hop."

    def circuit_built(self, circuit):
        "A circuit has been extended to all hops (usually 3 for user circuits)."

    def circuit_closed(self, circuit):
        "A circuit has been closed cleanly (won't be in controller's list any more)."
        
    def circuit_failed(self, circuit, reason):
        """A circuit has been closed because something went wrong.

        The circuit won't be in the TorState's list anymore. The
        reason comes from Tor (see tor-spec.txt). It is one of the
        following strings: MISC, RESOLVEFAILED, CONNECTREFUSED,
        EXITPOLICY, DESTROY, DONE, TIMEOUT, NOROUTE, HIBERNATING,
        INTERNAL,RESOURCELIMIT, CONNRESET, TORPROTOCOL, NOTDIRECTORY,
        END, PRIVATE_ADDR.

        However, don't depend on that: it could be anything.        
        """

class ITorControlProtocol(Interface):
    """
    This defines the API to the TorController object.

    This is the usual entry-point to this library, and you shouldn't
    need to call methods outside this interface.
    """

    def get_info(self, info):
        """
        :return: a Deferred which will callback with the info keys you
           asked for. For values ones, see control-spec.
        """

    def get_conf(self, *args):
        """
        Returns one or many configuration values via Deferred. See
        control-spec for valid keys. The value will be a dictionary.
        """

    def signal(self, signal_name):
        """
        Issues a signal to Tor. See control-spec or .valid_signals for
        which ones are available and their return values.
        """

    def build_circuit(self, routers):
        """
        Builds a circuit consisting of exactly the routers specified,
        in order.  This issues a series of EXTENDCIRCUIT calls to Tor;
        the deferred returned from this is for the final
        EXTEND. FIXME: should return the Circuit instance, but
        currently returns final extend message 'EXTEND 1234' for
        example.
        """

    def add_circuit_listener(self, icircuitlistener):
        """
        Add an implementor of :class:`txtorcon.interface.ICircuitListener` which will be
        added to all new circuits as well as all existing ones (you
        won't, however, get circuit_new calls for the existing ones)
        """
        
    def add_stream_listener(self, istreamlistener):
        """
        Add an implementor of :class:`txtorcon.interface.IStreamListener` which will be added to
        all new circuits as well as all existing ones (you won't,
        however, get stream_new calls for the existing ones)
        """
        
    def add_event_listener(self, evt, callback):
        """
        Add a listener to an Event object. This may be called multiple
        times for the same event. Every time the event happens, the
        callback method will be called. The callback has one argument
        (a string, the contents of the event, minus the "650" and the name of the event)

        FIXME: should have an interface for the callback.
        """

class IRouterContainer(Interface):
    def router_from_id(self, routerid):
        """
        :return: a router by its ID.
        """
