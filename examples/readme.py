from twisted.internet.task import react
from twisted.internet.defer import inlineCallbacks
from twisted.internet.endpoints import TCP4ClientEndpoint
import treq
import txtorcon

@react
@inlineCallbacks
def main(reactor):

    def update(percent, tag, summary):
        print("{}%: {}".format(int(percent), summary))
    tor = yield txtorcon.launch(
        reactor,
        progress_updates=update,
        data_directory='./tordata',
    )

    print("Tor started: {}".format(tor))

    # make a request via Tor
    resp = yield treq.get(
        'https://www.torproject.org:443',
        agent=tor.web_agent(),
    )

    print("Retrieving {} bytes".format(resp.length))
    data = yield resp.text()
    print("Got {} bytes:\n{}\n[...]{}".format(
        len(data),
        data[:120],
        data[-120:],
    ))

    # create a new circuit
    print("creating circuit")
    state = yield tor.create_state()
    circ = yield state.build_circuit()
    yield circ.when_built()
    print("  path: {}".format(" -> ".join([r.ip for r in circ.path])))

    # make a request via our new circuit
    print("Downloading meejah's public key...")
    resp = yield treq.get(
        'https://meejah.ca/meejah.asc',
        agent=circ.web_agent(reactor, tor.config.socks_endpoint(reactor)),
    )
    data = yield resp.text()
    print(data)
