"""The verdict verifier: every check, in order, and the nonce store behind it.

Most tests sign their own tokens with keys made here, so they can produce what the
mock never would (a production kid, a future iat, an `aud`, a missing mandate).
The key set is served through a fake httpx transport that counts fetches.
"""

from __future__ import annotations

import base64
import itertools
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import fakeredis
import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm
from jwt.api_jws import PyJWS

from spend_guard.clock import FakeClock
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
    VerificationError,
)
from spend_guard.jsonutil import dumps
from spend_guard.jwks import KeySet
from spend_guard.models import Order
from spend_guard.nonces import NonceStore, RedisNonceStore, SqliteNonceStore
from spend_guard.verify import ISSUER, MAX_TOKEN_BYTES, verify_verdict
from tests.mock_api.conftest import Mock
from tests.spend_guard.conftest import mock_keyset

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
PROD_KID = "verdict-2026-10"
SANDBOX_KID = "sandbox-2026-10"
MANDATE = "mnd_7f3a"
DEAL = Order(
    order_id="o-1",
    amount=Decimal("340.00"),
    currency="USD",
    recipient="vendor:acme_saas",
    category="saas",
)
_nonces = itertools.count(1)


class Keys:
    """Signing keys by kid, and a published set served by a fake transport."""

    def __init__(self) -> None:
        self.private: dict[str, ec.EllipticCurvePrivateKey] = {}
        self.published: list[dict[str, Any]] = []
        self.status = 200
        self.headers: dict[str, str] = {}

    def make(self, kid: str, *, publish: bool = True) -> None:
        self.private[kid] = ec.generate_private_key(ec.SECP256R1())
        if publish:
            self.publish(kid)

    def publish(self, kid: str) -> None:
        public = ECAlgorithm.to_jwk(self.private[kid].public_key(), as_dict=True)
        self.published.append({**public, "kid": kid, "alg": "ES256", "use": "sig"})

    def sign(self, claims: dict[str, Any], kid: str = PROD_KID, **header: Any) -> str:
        headers = {"kid": kid, "typ": "JWT", **header}
        return PyJWS().encode(
            dumps(claims).encode(), self.private[kid], algorithm="ES256", headers=headers
        )

    def keyset(self, **settings: Any) -> KeySet:
        def serve(request: httpx.Request) -> httpx.Response:
            return httpx.Response(self.status, json={"keys": self.published}, headers=self.headers)

        http = httpx.Client(transport=httpx.MockTransport(serve))
        return KeySet("https://keys.test/.well-known/jwks.json", http=http, **settings)


def approval(**overrides: Any) -> dict[str, Any]:
    """A valid allow for DEAL, issued now. Pass a claim as None to leave it out."""
    iat = int(NOW.timestamp())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "jti": "dec_5b2e",
        "iat": iat,
        "exp": iat + 300,
        "verdict": "allow",
        "mandate": MANDATE,
        "policy_version": "pol_2026-08-12.1",
        "nonce": f"n_{next(_nonces)}",
        "request": {
            "agent": "agt_procurement_01",
            "amount": Decimal("340.00"),
            "currency": "USD",
            "recipient": "vendor:acme_saas",
            "category": "saas",
        },
    }
    claims.update(overrides)
    return {name: value for name, value in claims.items() if value is not None}


class Harness:
    def __init__(self) -> None:
        self.keys = Keys()
        self.keys.make(PROD_KID)
        self.keys.make(SANDBOX_KID)
        self.jwks = self.keys.keyset()
        self.store = SqliteNonceStore()
        self.clock = FakeClock(NOW)

    def verify(self, token: str, deal: Any = DEAL, **options: Any) -> dict[str, Any]:
        settings: dict[str, Any] = {
            "jwks": self.jwks,
            "nonce_store": self.store,
            "accepted_mandates": [MANDATE],
            "clock": self.clock,
        }
        settings.update(options)
        return verify_verdict(token, deal, **settings)

    def nonce_recorded(self, claims: dict[str, Any]) -> bool:
        return self.store.seen(f"nonce:{claims['nonce']}", self.clock.now())


@pytest.fixture
def h() -> Harness:
    return Harness()


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# The happy path


def test_valid_approval_is_accepted_and_nonce_recorded(h: Harness) -> None:
    """R-209, R-204: a valid allow passes every check, and only then is its nonce recorded"""
    claims = approval(request={**approval()["request"], "amount": Decimal("340.50")})
    verified = h.verify(h.keys.sign(claims), deal=DEAL.model_copy(update={"amount": "340.50"}))
    assert verified["request"]["amount"] == Decimal("340.50")
    assert isinstance(verified["request"]["amount"], Decimal)  # parsed exactly, never a float
    assert h.nonce_recorded(claims)


# Step 0: format


@pytest.mark.parametrize(
    "mangle",
    [
        lambda t: t + "=",  # padding
        lambda t: t.replace(".", ". ", 1),  # whitespace
        lambda t: t.replace(".", "\n.", 1),
        lambda t: ".".join(t.split(".")[:2]),  # two segments
        lambda t: t + ".AAAA",  # four segments
        lambda t: "",
    ],
)
def test_malformed_tokens_rejected(h: Harness, mangle: Callable[[str], str]) -> None:
    """R-191: padded, whitespace-broken or wrongly segmented tokens are rejected"""
    with pytest.raises(TokenFormatError):
        h.verify(mangle(h.keys.sign(approval())))


def test_oversized_token_rejected(h: Harness) -> None:
    """R-190: a token over the size limit is rejected before anything is decoded"""
    claims = approval(request={**approval()["request"], "recipient": "x" * MAX_TOKEN_BYTES})
    with pytest.raises(TokenFormatError, match="bytes"):
        h.verify(h.keys.sign(claims))
    assert h.jwks.fetches == 0


# Step 1: key, signature, issuer, required claims


def test_tampered_token_rejected(h: Harness) -> None:
    """R-192: a token whose payload was changed after signing fails the signature check"""
    header, payload, signature = h.keys.sign(approval()).split(".")
    bigger = approval(request={**approval()["request"], "amount": Decimal("3400.00")})
    forged = ".".join([header, b64(dumps(bigger).encode()), signature])
    with pytest.raises(SignatureError):
        h.verify(forged, deal=DEAL.model_copy(update={"amount": Decimal("3400.00")}))


def test_signed_by_another_key_under_a_known_kid(h: Harness) -> None:
    """R-192: a valid-looking signature from a key that isn't the published one is rejected"""
    h.keys.make("impostor", publish=False)
    header, payload, _ = h.keys.sign(approval()).split(".")
    _, _, signature = h.keys.sign(approval(), kid="impostor").split(".")
    with pytest.raises(SignatureError):
        h.verify(".".join([header, payload, signature]))


@pytest.mark.parametrize("alg", ["HS256", "none", "ES384"])
def test_only_es256_accepted(h: Harness, alg: str) -> None:
    """R-192: any algorithm other than ES256 is rejected"""
    header = b64(dumps({"alg": alg, "typ": "JWT", "kid": PROD_KID}).encode())
    _, payload, signature = h.keys.sign(approval()).split(".")
    with pytest.raises(SignatureError, match="ES256"):
        h.verify(".".join([header, payload, signature]))


def test_wrong_issuer_rejected(h: Harness) -> None:
    """R-192: a token whose iss isn't https://verdicts.agent-spend-guard.local is rejected"""
    with pytest.raises(SignatureError, match="issuer"):
        h.verify(h.keys.sign(approval(iss="https://example.com")))


@pytest.mark.parametrize("claim", ["exp", "iat", "nonce", "verdict", "request"])
def test_missing_required_claim_rejected(h: Harness, claim: str) -> None:
    """R-193: exp, iat, iss, nonce, verdict and request are required"""
    with pytest.raises(TokenFormatError, match=claim):
        h.verify(h.keys.sign(approval(**{claim: None})))


def test_webhook_event_never_passes_as_verdict(make_mock: Callable[..., Mock]) -> None:
    """R-194: a genuine, correctly signed webhook event is rejected by the verdict check"""
    mock = make_mock()
    _, key, _ = mock.agent_with_mandate()
    mock.register_webhook(["decision.review_pending"])
    mock.review(key)
    mock.state.tick()
    [(_, event_token, _)] = mock.sender.calls
    with pytest.raises(TokenFormatError, match="exp, nonce"):
        verify_verdict(
            event_token, DEAL, jwks=mock_keyset(mock), nonce_store=SqliteNonceStore(),
            accepted_mandates=[MANDATE], allow_sandbox=True, clock=mock.clock,
        )  # fmt: skip


# The key set


def test_unknown_kid_refetches_once_then_rejects(h: Harness) -> None:
    """R-195: an unknown kid triggers exactly one refetch, then the token is rejected"""
    h.verify(h.keys.sign(approval()))
    assert h.jwks.fetches == 1
    h.keys.make("verdict-2026-11", publish=False)
    with pytest.raises(SignatureError, match="verdict-2026-11"):
        h.verify(h.keys.sign(approval(), kid="verdict-2026-11"))
    assert h.jwks.fetches == 2


def test_rotated_key_found_on_refetch(h: Harness) -> None:
    """R-195: a key published after the set was cached is found by the one refetch"""
    h.verify(h.keys.sign(approval()))
    h.keys.make("verdict-2026-11")  # published now, after the cache was filled
    h.verify(h.keys.sign(approval(), kid="verdict-2026-11"))
    assert h.jwks.fetches == 2


def test_unknown_kids_do_not_hammer_the_key_set(h: Harness) -> None:
    """R-196: after one refetch, further unknown kids within the cooldown fetch nothing"""
    h.verify(h.keys.sign(approval()))
    h.keys.make("ghost", publish=False)
    for _ in range(5):
        with pytest.raises(SignatureError):
            h.verify(h.keys.sign(approval(), kid="ghost"))
    assert h.jwks.fetches == 2


def test_duplicate_kid_rejected(h: Harness) -> None:
    """R-197: a kid listed twice in the set is rejected rather than taking the first"""
    h.keys.publish(PROD_KID)
    with pytest.raises(SignatureError, match="more than once"):
        h.verify(h.keys.sign(approval()))


def test_key_set_cached_for_five_minutes(h: Harness) -> None:
    """R-198: the set is cached (300 s lifespan), so verifying many tokens fetches it once"""
    assert h.jwks.jwk_set_cache is not None and h.jwks.jwk_set_cache.lifespan == 300
    for _ in range(3):
        h.verify(h.keys.sign(approval()))
    assert h.jwks.fetches == 1


@pytest.mark.parametrize("status", [301, 302, 500])
def test_key_set_redirect_or_error_rejects(h: Harness, status: int) -> None:
    """R-199: a redirect is never followed for key material; no key set means no approval"""
    h.keys.status, h.keys.headers = status, {"Location": "https://elsewhere.test/jwks.json"}
    with pytest.raises(SignatureError, match="could not fetch"):
        h.verify(h.keys.sign(approval()))


# Steps 2 to 9


def test_sandbox_kid_rejected_in_production(h: Harness) -> None:
    """R-200: a sandbox- kid is never a production approval; allowed only when configured"""
    claims = approval()
    token = h.keys.sign(claims, kid=SANDBOX_KID)
    with pytest.raises(SandboxKidError):
        h.verify(token)
    assert not h.nonce_recorded(claims)
    h.verify(token, allow_sandbox=True)


def test_future_iat_rejected_beyond_60_seconds(h: Harness) -> None:
    """R-201: iat up to 60 s in the future is accepted, 61 s is rejected"""
    now = int(NOW.timestamp())
    h.verify(h.keys.sign(approval(iat=now + 60, exp=now + 360)))
    with pytest.raises(FutureIatError):
        h.verify(h.keys.sign(approval(iat=now + 61, exp=now + 361)))


@pytest.mark.parametrize("verdict", ["review", "deny_limit", "deny_future_rule", "Allow"])
def test_anything_but_allow_rejected(h: Harness, verdict: str) -> None:
    """R-202: any verdict other than allow, including an unknown one, is not an approval"""
    with pytest.raises(NotAnApprovalError):
        h.verify(h.keys.sign(approval(verdict=verdict)))


def test_expired_at_exp_with_no_leeway(h: Harness) -> None:
    """R-203: accepted one second before exp; rejected at exp"""
    early = h.keys.sign(approval())
    late = h.keys.sign(approval())
    h.clock.advance(seconds=299)
    h.verify(early)
    h.clock.advance(seconds=1)
    with pytest.raises(ExpiredError):
        h.verify(late)


@pytest.mark.parametrize(
    "request_change",
    [
        {"amount": Decimal("340.01")},
        {"amount": "340.00"},  # a string is not a number
        {"currency": "usd"},
        {"currency": None},  # a token from before currency was signed
        {"recipient": "vendor:acme_saas "},
        {"recipient": "vendor:other"},
    ],
)
def test_claims_mismatch_rejected(h: Harness, request_change: dict[str, Any]) -> None:
    """R-204, R-205: amount, currency and recipient must match the deal exactly"""
    request = {**approval()["request"], **request_change}
    request = {name: value for name, value in request.items() if value is not None}
    with pytest.raises(ClaimsMismatchError):
        h.verify(h.keys.sign(approval(request=request)))


def test_amount_compared_as_decimal_value(h: Harness) -> None:
    """R-204: 340 in the token equals 340.00 in the order; large amounts stay exact"""
    h.verify(h.keys.sign(approval(request={**approval()["request"], "amount": 340})))
    big = DEAL.model_copy(update={"amount": Decimal("8589934592.000002")})
    request = {**approval()["request"], "amount": Decimal("8589934592.000001")}
    with pytest.raises(ClaimsMismatchError):  # the same double, but not the same amount
        h.verify(h.keys.sign(approval(request=request)), deal=big)


@pytest.mark.parametrize("mandate", ["mnd_other", None])
def test_unknown_or_missing_mandate_rejected(h: Harness, mandate: str | None) -> None:
    """R-206, R-208: the mandate must be one the operator gave us; an allow must name one"""
    with pytest.raises(UnknownMandateError):
        h.verify(h.keys.sign(approval(mandate=mandate)))


def test_audience_rejected_unless_it_names_us(h: Harness) -> None:
    """R-207: a token with aud is rejected unless it names us"""
    with pytest.raises(AudienceError):
        h.verify(h.keys.sign(approval(aud="shop.example")))
    with pytest.raises(AudienceError):
        h.verify(h.keys.sign(approval(aud="other.example")), audience="shop.example")
    h.verify(h.keys.sign(approval(aud=["shop.example"])), audience="shop.example")


def test_second_approval_of_one_review_refused(h: Harness) -> None:
    """R-208: a second allow whose supersedes was already accepted is refused"""
    h.verify(h.keys.sign(approval(supersedes="dec_review_1")))
    second = approval(supersedes="dec_review_1")
    with pytest.raises(SupersedesError):
        h.verify(h.keys.sign(second))
    assert not h.nonce_recorded(second)


def test_supersedes_remembered_for_25_hours(h: Harness) -> None:
    """R-213: an approval of a review is remembered 25 hours, past the review's own 24"""
    h.verify(h.keys.sign(approval(supersedes="dec_review_1")))
    h.clock.advance(hours=24, minutes=59)
    now = int(h.clock.now().timestamp())
    late = approval(supersedes="dec_review_1", iat=now, exp=now + 300)
    with pytest.raises(SupersedesError):
        h.verify(h.keys.sign(late))
    h.clock.advance(minutes=1)
    later = approval(supersedes="dec_review_1", iat=now + 60, exp=now + 360)
    h.verify(h.keys.sign(later))


# Step 10: the nonce


def test_replay_rejected(h: Harness) -> None:
    """R-209: the same approval presented twice is accepted once"""
    token = h.keys.sign(approval())
    h.verify(token)
    with pytest.raises(ReplayError):
        h.verify(token)


def test_failed_check_never_records_the_nonce(h: Harness) -> None:
    """R-209: a token that fails any check keeps its nonce unburned"""
    claims = approval(aud="other.example")  # passes every check up to step 8
    token = h.keys.sign(claims)
    with pytest.raises(AudienceError):
        h.verify(token)
    assert not h.nonce_recorded(claims)
    h.verify(token, audience="other.example")  # still usable once the check passes


def test_nonce_kept_for_600_seconds(h: Harness) -> None:
    """R-211: an accepted nonce is remembered at least 600 s (past exp plus skew)"""
    claims = approval()
    h.verify(h.keys.sign(claims))
    h.clock.advance(seconds=599)
    assert h.nonce_recorded(claims)
    h.clock.advance(seconds=1)
    assert not h.nonce_recorded(claims)


def test_check_order(h: Harness) -> None:
    """R-214: a token failing several checks is rejected by the earliest, named"""
    now = int(NOW.timestamp())
    cases: list[tuple[type[VerificationError], dict[str, Any], str]] = [
        (SandboxKidError, approval(verdict="review", iat=now + 120), SANDBOX_KID),
        (FutureIatError, approval(verdict="review", iat=now + 120), PROD_KID),
        (NotAnApprovalError, approval(verdict="review", exp=now), PROD_KID),
        (ExpiredError, approval(exp=now, mandate="mnd_other"), PROD_KID),
        (ClaimsMismatchError, approval(mandate="mnd_other", request={}), PROD_KID),
        (UnknownMandateError, approval(mandate="mnd_other", aud="x"), PROD_KID),
    ]
    for expected, claims, kid in cases:
        with pytest.raises(expected):
            h.verify(h.keys.sign(claims, kid=kid))


# Shared stores and concurrency


def present_concurrently(verifiers: list[Callable[[], Any]]) -> list[str]:
    barrier = threading.Barrier(len(verifiers))
    outcomes: list[str] = []

    def run(verify: Callable[[], Any]) -> None:
        barrier.wait()
        try:
            verify()
            outcomes.append("accepted")
        except ReplayError:
            outcomes.append("replay")

    threads = [threading.Thread(target=run, args=(verify,)) for verify in verifiers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return outcomes


def test_concurrent_replay_two_verifiers_share_a_store(h: Harness, tmp_path: Any) -> None:
    """R-210, R-212: one approval presented at once to two verifiers sharing a nonce store
    (two connections to one SQLite file) is accepted exactly once"""
    path = str(tmp_path / "nonces.db")
    for _ in range(20):
        token = h.keys.sign(approval())
        stores = [SqliteNonceStore(path), SqliteNonceStore(path)]
        verifiers = [lambda s=s, t=token: h.verify(t, nonce_store=s) for s in stores]
        assert sorted(present_concurrently(verifiers)) == ["accepted", "replay"]


def test_redis_store_is_atomic_and_shared(h: Harness) -> None:
    """R-210, R-212: the Redis backend records set-if-absent, all keys or none"""
    server = fakeredis.FakeServer()
    stores: list[NonceStore] = [
        RedisNonceStore(fakeredis.FakeRedis(server=server)) for _ in range(2)
    ]
    token = h.keys.sign(approval())
    h.verify(token, nonce_store=stores[0])
    with pytest.raises(ReplayError):
        h.verify(token, nonce_store=stores[1])
    # A conflict on the second key records nothing, not even the first.
    assert stores[0].add({"a": 600, "nonce:x": 600}, NOW) is None
    assert stores[1].add({"b": 600, "a": 600}, NOW) == "a"
    assert not stores[1].seen("b", NOW)


def test_sqlite_store_records_all_keys_or_none(h: Harness) -> None:
    """R-210: a conflict on any key rolls back the whole add"""
    assert h.store.add({"a": 600}, NOW) is None
    assert h.store.add({"b": 600, "a": 600}, NOW) == "a"
    assert not h.store.seen("b", NOW)
