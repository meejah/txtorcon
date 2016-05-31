# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function
from __future__ import with_statement

import os
import functools
import warnings
from io import StringIO
from collections import OrderedDict

from twisted.python import log
from twisted.internet import defer
from twisted.internet.endpoints import TCP4ClientEndpoint, UNIXClientEndpoint

from txtorcon.torcontrolprotocol import parse_keywords, DEFAULT_VALUE
from txtorcon.torcontrolprotocol import TorProtocolError
from txtorcon.util import py3k
from txtorcon.interface import ITorControlProtocol
from txtorcon.onion import FilesystemHiddenService, IOnionClient
from txtorcon.onion import AuthenticatedHiddenService, EphemeralHiddenService


class TorConfigType(object):
    """
    Base class for all configuration types, which function as parsers
    and un-parsers.
    """

    def parse(self, s):
        """
        Given the string s, this should return a parsed representation
        of it.
        """
        return s

    def validate(self, s, instance, name):
        """
        If s is not a valid type for this object, an exception should
        be thrown. The validated object should be returned.
        """
        return s


class Boolean(TorConfigType):
    "Boolean values are stored as 0 or 1."
    def parse(self, s):
        if int(s):
            return True
        return False

    def validate(self, s, instance, name):
        if s:
            return 1
        return 0


class Boolean_Auto(TorConfigType):
    """
    weird class-name, but see the parser for these which is *mostly*
    just the classname <==> string from Tor, except for something
    called Boolean+Auto which is replace()d to be Boolean_Auto
    """

    def parse(self, s):
        if s == 'auto' or int(s) < 0:
            return -1
        if int(s):
            return 1
        return 0

    def validate(self, s, instance, name):
        # FIXME: Is 'auto' an allowed value? (currently not)
        s = int(s)
        if s < 0:
            return 'auto'
        elif s:
            return 1
        else:
            return 0


class Integer(TorConfigType):
    def parse(self, s):
        return int(s)

    def validate(self, s, instance, name):
        return int(s)


class SignedInteger(Integer):
    pass


class Port(Integer):
    pass


class TimeInterval(Integer):
    pass


# not actually used?
class TimeMsecInterval(TorConfigType):
    pass


class DataSize(Integer):
    pass


class Float(TorConfigType):
    def parse(self, s):
        return float(s)


# unused also?
class Time(TorConfigType):
    pass


class CommaList(TorConfigType):
    def parse(self, s):
        return [x.strip() for x in s.split(',')]


# FIXME: in latest master; what is it?
# Tor source says "A list of strings, separated by commas and optional
# whitespace, representing intervals in seconds, with optional units"
class TimeIntervalCommaList(CommaList):
    pass


# FIXME: is this really a comma-list?
class RouterList(CommaList):
    pass


class String(TorConfigType):
    pass


class Filename(String):
    pass


class LineList(TorConfigType):
    def parse(self, s):
        if isinstance(s, list):
            return [str(x).strip() for x in s]
        return [x.strip() for x in s.split('\n')]

    def validate(self, obj, instance, name):
        if not isinstance(obj, list):
            raise ValueError("Not valid for %s: %s" % (self.__class__, obj))
        return _ListWrapper(
            obj, functools.partial(instance.mark_unsaved, name))

config_types = [Boolean, Boolean_Auto, LineList, Integer, SignedInteger, Port,
                TimeInterval, TimeMsecInterval,
                DataSize, Float, Time, CommaList, String, LineList, Filename,
                RouterList, TimeIntervalCommaList]


def is_list_config_type(klass):
    return 'List' in klass.__name__ or klass.__name__ in ['HiddenServices']


def _wrapture(orig):
    """
    Returns a new method that wraps orig (the original method) with
    something that first calls on_modify from the
    instance. _ListWrapper uses this to wrap all methods that modify
    the list.
    """

#    @functools.wraps(orig)
    def foo(*args):
        obj = args[0]
        obj.on_modify()
        return orig(*args)
    return foo


class _ListWrapper(list):
    """
    Do some voodoo to wrap lists so that if you do anything to modify
    it, we mark the config as needing saving.

    FIXME: really worth it to preserve attribute-style access? seems
    to be okay from an exterior API perspective....
    """

    def __init__(self, thelist, on_modify_cb):
        list.__init__(self, thelist)
        self.on_modify = on_modify_cb

    __setitem__ = _wrapture(list.__setitem__)
    append = _wrapture(list.append)
    extend = _wrapture(list.extend)
    insert = _wrapture(list.insert)
    remove = _wrapture(list.remove)
    pop = _wrapture(list.pop)

    def __repr__(self):
        return '_ListWrapper' + super(_ListWrapper, self).__repr__()

if not py3k:
    setattr(_ListWrapper, '__setslice__', _wrapture(list.__setslice__))


class TorConfig(object):
    """This class abstracts out Tor's config, and can be used both to
    create torrc files from nothing and track live configuration of a Tor
    instance.

    Also, it gives easy access to all the configuration options
    present. This is initialized at "bootstrap" time, providing
    attribute-based access thereafter. Note that after you set some
    number of items, you need to do a save() before these are sent to
    Tor (and then they will be done as one SETCONF).

    You may also use this class to construct a configuration from
    scratch (e.g. to give to :func:`txtorcon.launch_tor`). In this
    case, values are reflected right away. (If we're not bootstrapped
    to a Tor, this is the mode).

    Note that you do not need to call save() if you're just using
    TorConfig to create a .torrc file or for input to launch_tor().

    This class also listens for CONF_CHANGED events to update the
    cached data in the event other controllers (etc) changed it.

    There is a lot of magic attribute stuff going on in here (which
    might be a bad idea, overall) but the *intent* is that you can
    just set Tor options and it will all Just Work. For config items
    that take multiple values, set that to a list. For example::

        conf = TorConfig(...)
        conf.SOCKSPort = [9050, 1337]
        conf.HiddenServices.append(HiddenService(...))

    (Incoming objects, like lists, are intercepted and wrapped).

    FIXME: when is CONF_CHANGED introduced in Tor? Can we do anything
    like it for prior versions?

    FIXME:

        - HiddenServiceOptions is special: GETCONF on it returns
        several (well, two) values. Besides adding the two keys 'by
        hand' do we need to do anything special? Can't we just depend
        on users doing 'conf.hiddenservicedir = foo' AND
        'conf.hiddenserviceport = bar' before a save() ?

        - once I determine a value is default, is there any way to
          actually get what this value is?

    """

    @staticmethod
    @defer.inlineCallbacks
    def from_protocol(proto):
        """
        This creates and returns a ready-to-go TorConfig instance from the
        given protocol, which should be an instance of
        TorControlProtocol.
        """
        cfg = TorConfig(control=proto)
        yield cfg.post_bootstrap
        defer.returnValue(cfg)

    def __init__(self, control=None):
        self.config = {}
        '''Current configuration, by keys.'''

        if control is None:
            self._protocol = None
            self.__dict__['_open_'] = None

        else:
            self._protocol = ITorControlProtocol(control)

        self.unsaved = OrderedDict()
        '''Configuration that has been changed since last save().'''

        self.parsers = {}
        '''Instances of the parser classes, subclasses of TorConfigType'''

        self.list_parsers = set(['hiddenservices', 'ephemeralonionservices'])
        '''All the names (keys from .parsers) that are a List of something.'''

        # during bootstrapping we decide whether we support the
        # following features. A thing goes in here if TorConfig
        # behaves differently depending upon whether it shows up in
        # "GETINFO config/names"
        self._supports = dict(
            HiddenServiceDirGroupReadable=False
        )

        self.post_bootstrap = defer.Deferred()
        if self.protocol:
            if self.protocol.post_bootstrap:
                self.protocol.post_bootstrap.addCallback(
                    self.bootstrap).addErrback(log.err)
            else:
                self.bootstrap()

        else:
            self.do_post_bootstrap(self)

        self.__dict__['_setup_'] = None

    @defer.inlineCallbacks
    def socks_endpoint(self, reactor, socks_config):
        """
        Creates a new TorSocksEndpoint instance given a valid
        configuration line for ``SocksPort``; if this configuration
        isn't already in the underlying tor, we add it. Note that this
        method may call :meth:`txtorcon.TorConfig.save()` on this instance.

        XXX socks_config should be .. i dunno, but there's fucking
        options and craziness, e.g. default Tor Browser Bundle is:
        ['9150 IPv6Traffic PreferIPv6 KeepAliveIsolateSOCKSAuth',
        '9155']

        XXX we could avoid the "maybe call .save()" thing; worth it?
        """
        yield self.post_bootstrap

        if socks_config is None:
            if len(self.SocksPort) == 0:
                raise RuntimeError(
                    "socks_port is None and Tor has no SocksPorts configured"
                )
            socks_config = self.SocksPort[0]
        else:
            if not any([socks_config in port for port in self.SocksPort]):
                # need to configure Tor
                self.SocksPort.append(socks_config)
                try:
                    yield self.save()
                except TorProtocolError as e:
                    extra = ''
                    if socks_config.startswith('unix:'):
                        # XXX so why don't we check this for the
                        # caller, earlier on?
                        extra = '\nNote Tor has specific ownship/permissions ' +\
                                'requirements for unix sockets and parent dir.'
                    raise RuntimeError(
                        "While configuring SOCKSPort to '{}', error from"
                        " Tor: {}{}".format(
                            socks_config, e, extra
                        )
                    )

        if socks_config.startswith('unix:'):
            socks_ep = UNIXClientEndpoint(reactor, socks_config[5:])
        else:
            # options like KeepAliveIsolateSOCKSAuth can be appended
            # to a SocksPort line...
            if ' ' in socks_config:
                socks_config = socks_config.split()[0]
            if ':' in socks_config:
                host, port = socks_config.split(':', 1)
                port = int(port)
            else:
                host = '127.0.0.1'
                port = int(socks_config)
            socks_ep = TCP4ClientEndpoint(reactor, host, port)
        defer.returnValue(socks_ep)

    def onion_create(self, ports, auth=None, directory=None, private_key=None):
        """
        Creates a new Onion service.

        :param ports: list of strings like "80 127.0.0.1:80"

        :param auth: None, or an IOnionAuthentication provider (in
            practice, an instance of :class:`OnionAuthBasic` or
            :class:`OnionAuthStealth`)

        :param directory: None means an ephemeral hidden service (the
            default). Otherwise, a "normal", persistent hidden-service
            using data in the provided directory (if the directory is
            empty, a new private key will be written there by Tor).

        :param private_key: If creating an ephemeral service, this can
            be provided. This will be something previously retrieved from
            the ``.private_key`` attribute of a HiddenService instance.

        :return: Deferred that fires with the HiddenService instance
            once it is configured.
        """
        # ephemeral service if directory is None
        # can't specify directory *and* private_key

    # FIXME should re-name this to "tor_protocol" to be consistent
    # with other things? Or rename the other things?
    """
    read-only access to TorControlProtocol. Call attach_protocol() to
    set it, which can only be done if we don't already have a
    protocol.
    """
    def _get_protocol(self):
        return self.__dict__['_protocol']
    protocol = property(_get_protocol)
    tor_protocol = property(_get_protocol)

    def attach_protocol(self, proto):
        """
        returns a Deferred that fires once we've set this object up to
        track the protocol. Fails if we already have a protocol.
        """
        if self._protocol is not None:
            raise RuntimeError("Already have a protocol.")
        # make sure we have nothing in self.unsaved
        self.save()
        self.__dict__['_protocol'] = proto

        # FIXME some of this is duplicated from ctor
        del self.__dict__['_open_']
        self.__dict__['post_bootstrap'] = defer.Deferred()
        if proto.post_bootstrap:
            proto.post_bootstrap.addCallback(self.bootstrap)
        return self.__dict__['post_bootstrap']

    def _update_proto(self, proto):
        """
        internal method, used by launch_tor to update the protocol after we're
        set up.
        """
        self.__dict__['_protocol'] = proto

    def __setattr__(self, name, value):
        """
        we override this so that we can provide direct attribute
        access to our config items, and move them into self.unsaved
        when they've been changed. hiddenservices have to be special
        unfortunately. the _setup_ thing is so that we can set up the
        attributes we need in the constructor without uusing __dict__
        all over the place.
        """

        def has_setup_attr(ob):
            return '_setup_' in ob.__dict__

        def has_open_attr(ob):
            return '_open_' in ob.__dict__

        def is_hidden_services(svc):
            return svc.lower() == "hiddenservices"

        if has_setup_attr(self):
            name = self._find_real_name(name)
            if not has_open_attr(self) and not is_hidden_services(name):
                value = self.parsers[name].validate(value, self, name)
            if isinstance(value, list):
                value = _ListWrapper(
                    value, functools.partial(self.mark_unsaved, name))

            name = self._find_real_name(name)
            self.unsaved[name] = value

        else:
            super(TorConfig, self).__setattr__(name, value)

    def _maybe_create_listwrapper(self, rn):
        if rn.lower() in self.list_parsers and rn not in self.config:
            self.config[rn] = _ListWrapper([], functools.partial(
                self.mark_unsaved, rn))

    def __getattr__(self, name):
        """
        on purpose, we don't return self.unsaved if the key is in there
        because I want the config to represent the running Tor not
        ``things which might get into the running Tor if save() were
        to be called''
        """
        rn = self._find_real_name(name)
        if '_open_' in self.__dict__ and rn in self.unsaved:
            return self.unsaved[rn]
        self._maybe_create_listwrapper(rn)
        return self.config[rn]

    def __contains__(self, item):
        if item in self.unsaved and '_open_' in self.__dict__:
            return True
        return item in self.config

    def __iter__(self):
        '''
        FIXME needs proper iterator tests in test_torconfig too
        '''
        for x in self.config.__iter__():
            yield x
        for x in self.__dict__['unsaved'].__iter__():
            yield x

    def get_type(self, name):
        """
        return the type of a config key.

        :param: name the key

        FIXME can we do something more-clever than this for client
        code to determine what sort of thing a key is?
        """

        # XXX FIXME uhm...how to do all the different types of hidden-services?
        if name.lower() == 'hiddenservices':
            return FilesystemHiddenService
        return type(self.parsers[name])

    def _conf_changed(self, arg):
        """
        internal callback. from control-spec:

        4.1.18. Configuration changed

          The syntax is:
             StartReplyLine *(MidReplyLine) EndReplyLine

             StartReplyLine = "650-CONF_CHANGED" CRLF
             MidReplyLine = "650-" KEYWORD ["=" VALUE] CRLF
             EndReplyLine = "650 OK"

          Tor configuration options have changed (such as via a SETCONF or
          RELOAD signal). KEYWORD and VALUE specify the configuration option
          that was changed.  Undefined configuration options contain only the
          KEYWORD.
        """

        conf = parse_keywords(arg, multiline_values=False)
        for (k, v) in conf.items():
            # v will be txtorcon.DEFAULT_VALUE already from
            # parse_keywords if it was unspecified
            real_name = self._find_real_name(k)
            if real_name in self.parsers:
                v = self.parsers[real_name].parse(v)
            self.config[real_name] = v

    def bootstrap(self, arg=None):
        '''
        This only takes args so it can be used as a callback. Don't
        pass an arg, it is ignored.
        '''
        try:
            self.protocol.add_event_listener(
                'CONF_CHANGED', self._conf_changed)
        except RuntimeError:
            # for Tor versions which don't understand CONF_CHANGED
            # there's nothing we can really do.
            log.msg(
                "Can't listen for CONF_CHANGED event; won't stay up-to-date "
                "with other clients.")
        d = self.protocol.get_info_raw("config/names")
        d.addCallback(self._do_setup)
        d.addCallback(self.do_post_bootstrap)
        d.addErrback(self.do_post_errback)

    def do_post_errback(self, f):
        self.post_bootstrap.errback(f)
        return None

    def do_post_bootstrap(self, arg):
        if not self.post_bootstrap.called:
            self.post_bootstrap.callback(self)
        return self

    def needs_save(self):
        return len(self.unsaved) > 0

    def mark_unsaved(self, name):
        name = self._find_real_name(name)
        if name in self.config and name not in self.unsaved:
            self.unsaved[name] = self.config[self._find_real_name(name)]

    def save(self):
        """
        Save any outstanding items. This returns a Deferred which will
        errback if Tor was unhappy with anything, or callback with
        this TorConfig object on success.
        """

        if not self.needs_save():
            return defer.succeed(self)

        args = []
        directories = []
        for (key, value) in self.unsaved.items():
            if key == 'HiddenServices':
                self.config['HiddenServices'] = value
                # using a list here because at least one unit-test
                # cares about order -- and conceivably order *could*
                # matter here, to Tor...
                services = []
                # authenticated services get flattened into the HiddenServices list...
                for hs in value:
                    if IOnionClient.providedBy(hs):
                        services.append(IOnionClient(hs).parent)
                    elif isinstance(hs, EphemeralHiddenService):
                        raise ValueError(
                            "Only txtorcon.HiddenService instances may be added"
                            " via TorConfig.hiddenservices; ephemeral services"
                            " must be created with 'create_onion_service'."
                        )
                    else:
                        services.append(hs)

                for hs in services:
                    for (k, v) in hs.config_attributes():
                        if k == 'HiddenServiceDir':
                            if v not in directories:
                                directories.append(v)
                                args.append(k)
                                args.append(v)
                            else:
                                raise RuntimeError("Trying to add hidden service with same HiddenServiceDir: %s" % v)
                        else:
                            args.append(k)
                            args.append(v)
                continue

            if isinstance(value, list):
                for x in value:
                    # FIXME XXX
                    if x is not DEFAULT_VALUE:
                        args.append(key)
                        args.append(str(x))

            else:
                args.append(key)
                args.append(value)

            # FIXME in future we should wait for CONF_CHANGED and
            # update then, right?
            real_name = self._find_real_name(key)
            if not isinstance(value, list) and real_name in self.parsers:
                value = self.parsers[real_name].parse(value)
            self.config[real_name] = value

        # FIXME might want to re-think this, but currently there's no
        # way to put things into a config and get them out again
        # nicely...unless you just don't assign a protocol
        if self.protocol:
            d = self.protocol.set_conf(*args)
            d.addCallback(self._save_completed)
            return d

        else:
            self._save_completed()
            return defer.succeed(self)

    def _save_completed(self, *args):
        '''internal callback'''
        self.__dict__['unsaved'] = {}
        return self

    def _find_real_name(self, name):
        keys = list(self.__dict__['parsers'].keys()) + list(self.__dict__['config'].keys())
        for x in keys:
            if x.lower() == name.lower():
                return x
        return name

    @defer.inlineCallbacks
    def _do_setup(self, data):
        for line in data.split('\n'):
            if line == "config/names=":
                continue

            (name, value) = line.split()
            if name in self._supports:
                self._supports[name] = True

            if name == 'HiddenServiceOptions':
                # set up the "special-case" hidden service stuff
                servicelines = yield self.protocol.get_conf_raw(
                    'HiddenServiceOptions')
                self._setup_hidden_services(servicelines)
                continue

            if value == 'Dependant':
                continue

            # there's a thing called "Boolean+Auto" which is -1 for
            # auto, 0 for false and 1 for true. could be nicer if it
            # was called AutoBoolean or something, but...
            value = value.replace('+', '_')

            inst = None
            # FIXME: put parser classes in dict instead?
            for cls in config_types:
                if cls.__name__ == value:
                    inst = cls()
            if not inst:
                raise RuntimeError("Don't have a parser for: " + value)
            v = yield self.protocol.get_conf(name)
            v = v[name]

            rn = self._find_real_name(name)
            self.parsers[rn] = inst
            if is_list_config_type(inst.__class__):
                self.list_parsers.add(rn)
                parsed = self.parsers[rn].parse(v)
                self.config[rn] = _ListWrapper(
                    parsed, functools.partial(self.mark_unsaved, rn))

            else:
                self.config[rn] = self.parsers[rn].parse(v)

        # get any ephemeral services we own, or detached services.
        # these are *not* _ListWrappers because we don't care if they
        # change, nothing in Tor's config exists for these (probably
        # begging the question: why are we putting them in here at all
        # then...?)
        try:
            ephemeral = yield self.protocol.get_info('onions/current')
        except Exception:
            self.config['EphemeralOnionServices'] = []
        else:
            onions = []
            for line in ephemeral['onions/current'].split('\n'):
                onion = line.strip()
                if onion:
                    onions.append(
                        EphemeralHiddenService(
                            self, None,  # no way to discover ports=
                            hostname=onion,
                            detach=False,
                            discard_key=True,  # we don't know it...
                        )
                    )
            self.config['EphemeralOnionServices'] = onions

        try:
            detached = yield self.protocol.get_info('onions/detached')
        except Exception:
            self.config['DetachedOnionServices'] = []
        else:
            onions = []
            for line in detached['onions/detached'].split('\n'):
                onion = line.strip()
                if onion:
                    onions.append(
                        EphemeralHiddenService(
                            self, None, hostname=onion, detach=True,
                            discard_key=True,
                        )
                    )
            self.config['DetachedOnionServices'] = onions
        defer.returnValue(self)

    def _setup_hidden_services(self, servicelines):

        def maybe_add_hidden_service():
            if directory is not None:
                if directory not in directories:
                    directories.append(directory)
                    if not auth:
                        service = FilesystemHiddenService(
                            self, directory, ports, auth, ver, group_read
                        )
                        hs.append(service)
                    else:
                        auth_type, clients = auth.split(' ', 1)
                        clients = clients.split(',')
                        parent_service = AuthenticatedHiddenService(
                            self, directory, ports, auth_type, clients, ver, group_read
                        )
                        for client_name in parent_service.client_names():
                            hs.append(parent_service.get_client(client_name))
                else:
                    raise RuntimeError("Trying to add hidden service with same HiddenServiceDir: %s" % directory)

        hs = []
        directory = None
        directories = []
        ports = []
        ver = None
        group_read = None
        auth = None
        for line in servicelines.split('\n'):
            if not len(line.strip()):
                continue

            if line == 'HiddenServiceOptions':
                continue
            k, v = line.split('=')
            if k == 'HiddenServiceDir':
                maybe_add_hidden_service()
                directory = v
                _directory = directory
                directory = os.path.abspath(directory)
                if directory != _directory:
                    warnings.warn(
                        "Directory path: %s changed to absolute path: %s" % (_directory, directory),
                        RuntimeWarning
                    )
                ports = []
                ver = None
                auth = None
                group_read = 0

            elif k == 'HiddenServicePort':
                ports.append(v)

            elif k == 'HiddenServiceVersion':
                ver = int(v)

            elif k == 'HiddenServiceAuthorizeClient':
                if auth is not None:
                    # definitely error, or keep going?
                    raise ValueError("Multiple HiddenServiceAuthorizeClient lines for one service")
                auth = v

            elif k == 'HiddenServiceDirGroupReadable':
                group_read = int(v)

            else:
                raise RuntimeError("Can't parse HiddenServiceOptions: " + k)

        maybe_add_hidden_service()

        name = 'HiddenServices'
        self.config[name] = _ListWrapper(
            hs, functools.partial(self.mark_unsaved, name))

    def config_args(self):
        '''
        Returns an iterator of 2-tuples (config_name, value), one for each
        configuration option in this config. This is more-or-less an
        internal method, but see, e.g., launch_tor()'s implementation
        if you think you need to use this for something.

        See :meth:`txtorcon.TorConfig.create_torrc` which returns a
        string which is also a valid ``torrc`` file
        '''

        for (k, v) in list(self.config.items()) + list(self.unsaved.items()):
            if type(v) is _ListWrapper:
                if k.lower() == 'hiddenservices':
                    for x in v:
                        for (kk, vv) in x.config_attributes():
                            yield (str(kk), str(vv))

                else:
                    # FIXME actually, is this right? don't we want ALL
                    # the values in one string?!
                    for x in v:
                        yield (str(k), str(x))

            else:
                yield (str(k), str(v))

    def create_torrc(self):
        rtn = StringIO()

        for (k, v) in self.config_args():
            rtn.write(u'%s %s\n' % (k, v))

        return rtn.getvalue()
