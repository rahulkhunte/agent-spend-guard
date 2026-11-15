"""Verify a verdict token before money moves.

`verify_verdict` runs the checks in this order, and the first failure raises its
own exception, so a rejection says which check failed:

 0. Format: size limit, three base64url segments, no padding or whitespace.
 1. Signature: the key named by `kid` (unknown: refetch the set once; listed
    twice: reject), ES256 only, issuer, and the required claims
    `exp, iat, iss, nonce, verdict, request`. A webhook event has no `exp` and
    no `nonce`, so it fails here and can never pass as a verdict.
 2. Environment: a `sandbox-` kid is rejected unless sandbox is allowed.
 3. Clock: `iat` more than 60 seconds in the future is rejected.
 4. Approval: `verdict` must be `allow`. Anything else, known or not, is rejected.
 5. Expiry: rejected from `exp` on, with no leeway.
 6. Deal: amount (exact decimal value), currency (case-sensitive) and recipient
    (exact) must match what is about to be settled.
 7. Operator: `mandate` must be present and one the operator gave us.
 8. Audience: a token with `aud` is rejected unless it names us.
 9. Structure: an allow with no mandate is rejected by step 7, and `supersedes`
    on a non-allow by step 4. A second `allow` for a review whose approval we
    already accepted is caught in step 10, in the same atomic step as the nonce.
10. Nonce, last: the nonce (and the `supersedes` of an approval) is recorded in
    one atomic step, and only now, so a token that failed a check never burns
    its nonce. A nonce already recorded is a replay; a `supersedes` already
    recorded is a second approval of the same review.

The payload is parsed with `Decimal` for every non-integer number, after the
signature check, so an amount is never rounded through a float.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from decimal import Decimal
from typing import Any, Protocol

from jwt.api_jws import PyJWS
from jwt.exceptions import PyJWKClientError, PyJWTError

from spend_guard.clock import Clock, SystemClock
from spend_guard.errors import (
    AudienceError,
    ClaimsMismatchError,
    ExpiredError,
    FutureIatError,
    NotAnApprovalError,
    ReplayError,
    SandboxKidError,
    SignatureError,
    SupersedesError,
    TokenFormatError,
    UnknownMandateError,
)
from spend_guard.jsonutil import loads, to_decimal
from spend_guard.jwks import KeySet
from spend_guard.nonces import NonceStore

ISSUER = "https://verdicts.agent-spend-guard.local"
VERDICT_CLAIMS = ("exp", "iat", "iss", "nonce", "verdict", "request")
# R-190: 16 KB fits the largest fields a token can carry (a 1,024-character recipient,
# even fully escaped) many times over.
MAX_TOKEN_BYTES = 16 * 1024
FUTURE_IAT_LEEWAY = 60  # seconds; there is no leeway on exp
NONCE_TTL = 600  # seconds; and never less than exp plus clock skew
# A review lives 24 hours and its approval 5 minutes, so remembering an accepted
# supersedes for 25 hours covers every approval that could still be presented.
SUPERSEDES_TTL = 25 * 3600

SEGMENT = re.compile(r"[A-Za-z0-9_-]+")


class Deal(Protocol):
    """What is about to be settled. An `Order` is one."""

    @property
    def amount(self) -> Decimal: ...
    @property
    def currency(self) -> str: ...
    @property
    def recipient(self) -> str: ...


def check_format(token: str) -> None:
    if not isinstance(token, str) or not token:
        raise TokenFormatError("token must be a non-empty string")
    if len(token.encode()) > MAX_TOKEN_BYTES:
        raise TokenFormatError(f"token is over {MAX_TOKEN_BYTES} bytes")
    segments = token.split(".")
    if len(segments) != 3 or not all(SEGMENT.fullmatch(segment) for segment in segments):
        raise TokenFormatError("token must be three unpadded base64url segments")


def decode_signed(
    token: str, jwks: KeySet, required: Iterable[str]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Steps 0 and 1, shared by verdicts and webhook events. Returns (header, claims)."""
    check_format(token)
    try:
        header = PyJWS().get_unverified_header(token)
    except PyJWTError as error:
        raise TokenFormatError(f"unreadable header: {error}") from error
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise TokenFormatError("header has no kid")
    if header.get("alg") != "ES256":
        raise SignatureError(f"algorithm {header.get('alg')!r} is not ES256")
    try:
        key = jwks.key_for(kid)
    except PyJWKClientError as error:
        raise SignatureError(f"no usable key for kid {kid}: {error}") from error
    try:
        payload = PyJWS().decode(token, key.key, algorithms=["ES256"])
    except PyJWTError as error:
        raise SignatureError(f"bad signature: {error}") from error
    try:
        claims = loads(payload)  # Decimal for amounts, only now that the signature holds
    except ValueError as error:
        raise TokenFormatError(f"payload is not JSON: {error}") from error
    if not isinstance(claims, dict):
        raise TokenFormatError("payload is not a JSON object")
    if claims.get("iss") != ISSUER:
        raise SignatureError(f"issuer {claims.get('iss')!r} is not {ISSUER}")
    missing = [name for name in required if name not in claims]
    if missing:
        raise TokenFormatError(f"missing required claims: {', '.join(missing)}")
    return header, claims


def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_types(claims: dict[str, Any]) -> None:
    request = claims["request"]
    if not (is_int(claims["exp"]) and is_int(claims["iat"])):
        raise TokenFormatError("exp and iat must be integers")
    if not (isinstance(claims["nonce"], str) and isinstance(claims["verdict"], str)):
        raise TokenFormatError("nonce and verdict must be strings")
    if not isinstance(request, dict):
        raise TokenFormatError("request must be an object")
    for name in ("mandate", "supersedes"):
        if name in claims and not isinstance(claims[name], str):
            raise TokenFormatError(f"{name} must be a string")


def _matches_deal(request: dict[str, Any], deal: Deal) -> bool:
    try:
        amount = to_decimal(request.get("amount"))
    except ValueError:
        return False
    return (
        amount == Decimal(deal.amount)  # compares values: 340 equals 340.00
        and request.get("currency") == deal.currency
        and request.get("recipient") == deal.recipient
    )


def verify_verdict(
    token: str,
    deal: Deal,
    *,
    jwks: KeySet,
    nonce_store: NonceStore,
    accepted_mandates: Iterable[str],
    allow_sandbox: bool = False,
    clock: Clock | None = None,
    audience: str | None = None,
) -> dict[str, Any]:
    """Run every check above. Returns the verified claims; raises a VerificationError
    subclass naming the first check that failed."""
    now = (clock or SystemClock()).now()
    now_ts = int(now.timestamp())

    header, claims = decode_signed(token, jwks, VERDICT_CLAIMS)  # steps 0 and 1
    _check_types(claims)

    if header["kid"].startswith("sandbox-") and not allow_sandbox:
        raise SandboxKidError(f"sandbox key {header['kid']}: never a production approval")
    if claims["iat"] > now_ts + FUTURE_IAT_LEEWAY:
        raise FutureIatError(f"iat is {claims['iat'] - now_ts} seconds in the future")
    if claims["verdict"] != "allow":
        raise NotAnApprovalError(f"not an approval: {claims['verdict']}")
    if now_ts >= claims["exp"]:
        raise ExpiredError("the verdict has expired")
    if not _matches_deal(claims["request"], deal):
        raise ClaimsMismatchError("approval is for a different amount, currency or recipient")

    mandate = claims.get("mandate")
    if mandate is None:
        raise UnknownMandateError("an allow must name a mandate")
    if mandate not in set(accepted_mandates):
        raise UnknownMandateError(f"mandate {mandate} is not one the operator gave us")

    if "aud" in claims:
        aud = claims["aud"]
        named = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
        if audience is None or audience not in named:
            raise AudienceError(f"token is addressed to {aud!r}, not to us")

    # Steps 9 and 10: only now, record the nonce (and the review it approves) in one step.
    supersedes = claims.get("supersedes")
    entries = {f"nonce:{claims['nonce']}": max(NONCE_TTL, claims["exp"] - now_ts + 60)}
    if supersedes is not None:
        entries[f"supersedes:{supersedes}"] = SUPERSEDES_TTL
    conflict = nonce_store.add(entries, now)
    if conflict is not None and conflict.startswith("nonce:"):
        raise ReplayError("replay: this approval was already used")
    if conflict is not None:
        raise SupersedesError(f"an approval of {supersedes} was already accepted")
    return claims


class VerdictVerifier:
    """`verify_verdict` with one integration's settings, in the shape the gate takes:
    `verifier(token, order)`."""

    def __init__(
        self,
        *,
        jwks: KeySet,
        nonce_store: NonceStore,
        accepted_mandates: Iterable[str],
        allow_sandbox: bool = False,
        clock: Clock | None = None,
        audience: str | None = None,
    ) -> None:
        self.jwks = jwks
        self.nonce_store = nonce_store
        self.accepted_mandates = set(accepted_mandates)
        self.allow_sandbox = allow_sandbox
        self.clock = clock or SystemClock()
        self.audience = audience

    def __call__(self, token: str, order: Deal) -> None:
        verify_verdict(
            token,
            order,
            jwks=self.jwks,
            nonce_store=self.nonce_store,
            accepted_mandates=self.accepted_mandates,
            allow_sandbox=self.allow_sandbox,
            clock=self.clock,
            audience=self.audience,
        )
