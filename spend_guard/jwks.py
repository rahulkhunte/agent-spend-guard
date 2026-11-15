"""The public key set, fetched with PyJWT's `PyJWKClient`.

`PyJWKClient` already does most of what SPEC section 16.1 asks of a key-set cache:
- it keeps the set for 5 minutes (`lifespan=300`), the set's own `max-age`
- on an unknown `kid` it fetches the set again, once, then gives up
- after that refetch it waits (`cooldown_seconds`) before refetching again, so a
  stream of tokens with unknown kids can't hammer the endpoint

Two things are added here:
- Fetching goes through httpx, with a timeout and without following redirects
  (following a redirect for key material would mean trusting whoever issued
  it). Tests pass the mock's in-process client.
- A `kid` that appears twice in the set is rejected; `PyJWKClient` would take the first.

This repo only ever points it at the local mock's `/.well-known/jwks.json`.
"""

from __future__ import annotations

from typing import Any

import httpx
from jwt import PyJWK, PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

MOCK_JWKS_URL = "http://127.0.0.1:8787/.well-known/jwks.json"


class KeySet(PyJWKClient):
    def __init__(
        self,
        url: str = MOCK_JWKS_URL,
        *,
        http: httpx.Client | None = None,
        timeout: float = 5.0,
        cooldown_seconds: float = 30.0,
    ) -> None:
        super().__init__(url, cache_jwk_set=True, lifespan=300, cooldown_duration=cooldown_seconds)
        self._http = http or httpx.Client(timeout=timeout, follow_redirects=False)
        self.fetches = 0  # how many times the set was fetched, for tests and logs

    def fetch_data(self) -> Any:
        self.fetches += 1
        try:
            response = self._http.get(self.uri)
            response.raise_for_status()  # a redirect is an error here, never followed
            return response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise PyJWKClientConnectionError(f"could not fetch the key set: {error}") from error

    def key_for(self, kid: str) -> PyJWK:
        """The key named `kid`. Raises PyJWKClientError if it is absent after one refetch,
        or listed more than once."""
        key = self.get_signing_key(kid)
        if sum(1 for listed in self.get_jwk_set().keys if listed.key_id == kid) > 1:
            raise PyJWKClientError(f"kid {kid} appears more than once in the key set")
        return key
