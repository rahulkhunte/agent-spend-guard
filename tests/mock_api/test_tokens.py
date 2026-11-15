"""The verdict token the mock signs, and the key set it publishes."""

from __future__ import annotations

import base64
from datetime import datetime
from decimal import Decimal

import jwt
import pytest
from jwt.api_jwk import PyJWK
from jwt.api_jws import PyJWS

from tests.mock_api.conftest import Mock


def test_token_header_and_signature(mock: Mock) -> None:
    """R-100: ES256, a `sandbox-` kid, and a signature that verifies against the published set;
    a tampered payload does not."""
    _, key, _ = mock.agent_with_mandate()
    token = mock.decide(key)["verdict_token"]
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "ES256"
    assert header["typ"] == "JWT"
    assert header["kid"].startswith("sandbox-")
    assert header["kid"] == mock.client.get("/.well-known/jwks.json").json()["keys"][0]["kid"]
    assert mock.claims(token)["verdict"] == "allow"

    head, payload, signature = token.split(".")
    tampered_payload = payload.replace(payload[10], "A" if payload[10] != "A" else "B", 1)
    with pytest.raises(jwt.InvalidSignatureError):
        mock.claims(f"{head}.{tampered_payload}.{signature}")


def test_claims_match_decision(mock: Mock) -> None:
    """R-036, R-037, R-101, R-104: the token signs the decision's id, time, request and ids."""
    _, key, mandate = mock.agent_with_mandate()
    decision = mock.decide(key)
    claims = mock.claims(decision["verdict_token"])
    assert claims["iss"] == "https://verdicts.agent-spend-guard.local"
    assert claims["jti"] == decision["decision"]
    issued = datetime.fromisoformat(decision["issued_at"].replace("Z", "+00:00"))
    assert claims["iat"] == int(issued.timestamp())
    assert claims["request"] == decision["request"]
    assert claims["mandate"] == mandate["mandate"]
    assert claims["policy_version"] == decision["policy_version"]
    assert claims["nonce"] == decision["nonce"]
    assert claims["verdict"] == decision["verdict"]


def test_denials_expire_in_300_seconds(mock: Mock) -> None:
    """R-102: every verdict, a denial included, has exp = iat + 300."""
    _, key, _ = mock.agent_with_mandate()
    for amount, category in (("720.00", "saas"), ("10", "travel"), ("340", "saas"), ("10", "saas")):
        decision = mock.decide(key, amount, category=category)
        claims = mock.claims(decision["verdict_token"])
        assert claims["exp"] - claims["iat"] == 300, decision["verdict"]


def test_unsigned_fields_and_no_aud(mock: Mock) -> None:
    """R-103: reason, mode, metadata and review are on the decision but not in the token;
    there is no aud claim."""
    _, key, _ = mock.agent_with_mandate()
    decision = mock.decide(key, "340.00", metadata={"order_id": "order-1"})
    assert {"reason", "mode", "metadata", "review"} <= set(decision)
    claims = mock.claims(decision["verdict_token"])
    assert not {"reason", "mode", "metadata", "review", "aud"} & set(claims)


def test_approval_token_has_supersedes(mock: Mock) -> None:
    """R-105: an approval's token signs `supersedes`; an ordinary allow's doesn't."""
    _, key, _ = mock.agent_with_mandate()
    original = mock.review(key)
    approval = mock.body(mock.post(f"/v1/reviews/{original['review']['review']}/approve"))
    assert mock.claims(approval["verdict_token"])["supersedes"] == original["decision"]
    assert "supersedes" not in mock.claims(mock.decide(key)["verdict_token"])


def test_amount_exact_in_token(mock: Mock) -> None:
    """R-107: an amount above 2^33 with six decimals is signed exactly; as a float it would round
    to its neighbour."""
    amount = "8589934592.000001"
    assert float(amount) == float("8589934592.000002")  # why floats are not allowed
    _, key, _ = mock.agent_with_mandate(
        limits={"per_transaction": Decimal("1e11"), "currency": "USD"}, review_above=None
    )
    decision = mock.decide(key, amount)
    assert decision["request"]["amount"] == Decimal(amount)
    payload = decision["verdict_token"].split(".")[1]
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    assert b'"amount":8589934592.000001' in raw
    signed = PyJWS().decode(
        decision["verdict_token"],
        PyJWK(mock.client.get("/.well-known/jwks.json").json()["keys"][0]).key,
        algorithms=["ES256"],
    )
    assert signed == raw


def test_jwks_cache_headers(mock: Mock) -> None:
    """R-106: the key set needs no key and is served with max-age=300 and open CORS."""
    response = mock.client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "max-age=300"
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    (key,) = response.json()["keys"]
    assert key["kty"] == "EC" and key["crv"] == "P-256" and key["alg"] == "ES256"
    assert "d" not in key  # never the private part
