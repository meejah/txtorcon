#!/usr/bin/env python

from twisted.web import server, resource, static
from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint, UNIXClientEndpoint

from nevow import loaders, tags, livepage, inevow

import txtorcon

torstate = None

def set_state(state):
    global torstate
    torstate = state

class TorPage(livepage.LivePage):
    addSlash = True

    continuous_update = False
    last_update = "Nothing yet..."
    ctx = None
    
    docFactory = loaders.stan(
        tags.html[
            tags.head[
                tags.directive('liveglue')],
            tags.body[
                tags.h1["Tor Launching..."],
                ## obviously you might want a javascript library or
                ## something here instead of this hackery to get
                ## actuall browser support, etc.
                tags.div(id='progress',style='position:absolute; left:20em; top:10px; width:300px; height:50px; border:2px solid black;background-color:#ffaaaa;')[
                    tags.div(id='progress_done',style='position:absolute; top:0px; left:0px; width:0%; height: 100%; background-color:#aaffaa;')],

                ## this is where the messages will go
                tags.div(id='status',style='padding:5px; background-color:#ffaaaa; text-indent:2em; width: 50em; font-weight:bold; border: 2px solid black;')[""]
                ]
            ]
        )

    def handle_updateStatus(self, ctx, percent):
        client = livepage.IClientHandle(ctx)

        point = int(300 * (float(percent) / 100.0))
        yield livepage.js('''document.getElementById('progress_done').style.width = "%dpx";''' % point)

        
        if percent == 100:
            ## done, turn box green
            yield livepage.js('''document.getElementById("status").style.backgroundColor="#aaffaa";''')
            
        if self.continuous_update:
            ## add a text node for each update, creating a continuous list
            yield livepage.js('''var newNode = document.createElement('div');
newNode.appendChild(document.createTextNode("%s"));
document.getElementById('status').appendChild(newNode);''' % self.last_update)
            
        else:
            yield livepage.set('status', str(self.last_update))
        
    def goingLive(self, ctx, client):
        '''
        Overrides nevow method; not really safe to just save ctx,
        client in self for multiple clients, but nice and simple.
        '''
        
        self.ctx = ctx
        self.client = client
        print 'going live:', client
        client.send(self.handle_updateStatus(ctx, 0))
        
    def tor_update(self, prog, tag, summary):
        '''
        We've received an update from Tor.
        '''

        upd = "%d%%: %s" % (prog, summary)
        print "tor update",upd
        self.last_update = upd
        if self.ctx:
            self.client.send(self.handle_updateStatus(self.ctx, prog))

top_level = TorPage()

config = txtorcon.TorConfig()
config.OrPort = 1234
config.SocksPort = 9999

d = txtorcon.launch_tor(config, reactor, progress_updates=top_level.tor_update)
d.addCallback(set_state)
#d.addErrback(setup_failed)

from nevow.appserver import NevowSite
site = NevowSite(top_level)
reactor.listenTCP(8080, site)
reactor.run()
