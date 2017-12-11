
class _AsyncOnionContext(object):
    def __init__(self, tor, onion_host, token):
        self._tor = tor
        self._host = onion_host
        self._token = token

    async def __aenter__(self):
        await self._tor.add_onion_authentication(self._host, self._token)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self._tor.remove_onion_authentication(self._host)

