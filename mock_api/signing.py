"""The mock's signing key: P-256, made fresh at startup, never written anywhere.

Verdicts and webhook events are both signed here with the same key, and
the public half is served as a JWK Set.
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm
from jwt.api_jws import PyJWS

from spend_guard.jsonutil import dumps

ISSUER = "https://verdicts.agent-spend-guard.local"


class Signer:
    def __init__(self, kid: str) -> None:
        if not kid.startswith("sandbox-"):
            raise ValueError("the mock behaves like sandbox: its kid must start with sandbox-")
        self.kid = kid
        self._private_key = ec.generate_private_key(ec.SECP256R1())

    def sign(self, claims: dict[str, Any]) -> str:
        """ES256 JWT. We serialize the claims ourselves so Decimal amounts stay exact numbers."""
        payload = dumps(claims).encode()
        headers = {"kid": self.kid, "typ": "JWT"}
        return PyJWS().encode(payload, self._private_key, algorithm="ES256", headers=headers)

    def jwks(self) -> dict[str, Any]:
        public = ECAlgorithm.to_jwk(self._private_key.public_key(), as_dict=True)
        return {"keys": [{**public, "kid": self.kid, "alg": "ES256", "use": "sig"}]}
