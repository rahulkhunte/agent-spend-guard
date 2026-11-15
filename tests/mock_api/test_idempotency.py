"""Idempotency: replays, conflicts, and which results are never stored."""

from __future__ import annotations

from decimal import Decimal

from tests.mock_api.conftest import Mock


def test_replay_returns_original_decision(mock: Mock) -> None:
    """R-070: same API key, Idempotency-Key and body replays the original decision."""
    _, key, _ = mock.agent_with_mandate()
    first = mock.authorize(key, idem="order-4412")
    second = mock.authorize(key, idem="order-4412")
    assert "Idempotency-Replayed" not in first.headers
    assert second.headers["Idempotency-Replayed"] == "true"
    assert second.status_code == 201
    assert mock.body(second) == mock.body(first)
    assert len(mock.export()) == 1


def test_replay_window_is_24_hours(mock: Mock) -> None:
    """R-071: inside 24 hours it replays; after 24 hours the same key is a new request."""
    _, key, _ = mock.agent_with_mandate()
    original = mock.body(mock.authorize(key, idem="order-1"))
    mock.clock.advance(hours=23, minutes=59, seconds=59)
    assert mock.body(mock.authorize(key, idem="order-1"))["decision"] == original["decision"]
    mock.clock.advance(seconds=1)
    fresh = mock.authorize(key, idem="order-1")
    assert "Idempotency-Replayed" not in fresh.headers
    assert mock.body(fresh)["decision"] != original["decision"]


def test_different_body_is_409(mock: Mock) -> None:
    """R-072: the same key with a different body is 409 idempotency_conflict."""
    _, key, _ = mock.agent_with_mandate()
    mock.authorize(key, "120.00", idem="order-2")
    response = mock.authorize(key, "121.00", idem="order-2")
    assert response.status_code == 409
    assert mock.body(response)["error"]["code"] == "idempotency_conflict"
    assert len(mock.export()) == 1


def test_different_api_key_is_new_request(mock: Mock) -> None:
    """R-073: idempotency is scoped to the API key; another key with the same Idempotency-Key
    gets its own decision."""
    _, key_a, _ = mock.agent_with_mandate()
    _, key_b, _ = mock.agent_with_mandate()
    a = mock.authorize(key_a, idem="shared-key")
    b = mock.authorize(key_b, idem="shared-key")
    assert b.status_code == 201
    assert "Idempotency-Replayed" not in b.headers
    assert mock.body(a)["decision"] != mock.body(b)["decision"]


def test_5xx_not_stored_retry_is_fresh(mock: Mock) -> None:
    """R-074: a 5xx is never stored, so a retry with the same key is evaluated fresh."""
    _, key, _ = mock.agent_with_mandate()
    mock.post("/_mock/faults", {"error_rate": Decimal("1")})
    failed = mock.authorize(key, idem="order-3")
    assert failed.status_code == 500
    assert mock.body(failed)["error"]["code"] == "server_error"
    assert mock.export() == []  # no decision was made

    mock.post("/_mock/faults", {"error_rate": Decimal("0")})
    retry = mock.authorize(key, idem="order-3")
    assert retry.status_code == 201
    assert "Idempotency-Replayed" not in retry.headers
    assert len(mock.export()) == 1


def test_4xx_stored_and_replayed(mock: Mock) -> None:
    """R-075: a 400 from the endpoint is stored and replayed; a corrected body under the same
    key is then 409, so the fix needs a new key."""
    _, key, _ = mock.agent_with_mandate()
    first = mock.authorize(key, "-5", idem="order-4")
    assert first.status_code == 400
    replay = mock.authorize(key, "-5", idem="order-4")
    assert replay.status_code == 400
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert mock.body(replay) == mock.body(first)
    assert mock.authorize(key, "5", idem="order-4").status_code == 409
    assert mock.authorize(key, "5", idem="order-4-fixed").status_code == 201


def test_401_403_429_not_stored(mock: Mock) -> None:
    """R-075: 401, 403 and 429 are never stored under the Idempotency-Key."""
    agent, key, _ = mock.agent_with_mandate()

    # 401: an unknown key is refused before any idempotency scope exists.
    assert mock.authorize("ak_sandbox_" + "f" * 32, idem="k-401").status_code == 401
    assert mock.authorize(key, idem="k-401").status_code == 201

    # 403: if it had been stored, a later different body under the key would be 409.
    assert mock.post(f"/v1/agents/{agent}/disable", key=key, idem="k-403").status_code == 403
    assert mock.authorize(key, idem="k-403").status_code == 201

    # 429: the retry after Retry-After is evaluated, not answered with the stored 429.
    mock.post("/_mock/faults", {"rate_limit_burst": 1})
    assert mock.authorize(key, idem="k-429").status_code == 429
    retry = mock.authorize(key, idem="k-429")
    assert retry.status_code == 201
    assert "Idempotency-Replayed" not in retry.headers


def test_pre_endpoint_refusals_not_stored(mock: Mock) -> None:
    """R-076: an oversized body, a bad Content-Length or an Idempotency-Key over 255 characters
    is refused before the endpoint and not stored."""
    _, key, _ = mock.agent_with_mandate()
    assert mock.authorize(key, idem="x" * 256).status_code == 400
    assert mock.authorize(key, idem="x" * 255).status_code == 201

    oversized = b'{"pad": "' + b"x" * (64 * 1024) + b'"}'
    response = mock.post("/v1/authorizations", key=key, idem="k-big", raw=oversized)
    assert response.status_code == 400
    assert mock.authorize(key, idem="k-big").status_code == 201  # not a 409

    headers = {"Authorization": f"Bearer {key}", "Idempotency-Key": "k-len"}
    bad = mock.client.post(
        "/v1/authorizations", content=b"{}", headers={**headers, "Content-Length": "abc"}
    )
    assert bad.status_code == 400
    assert mock.authorize(key, idem="k-len").status_code == 201  # not a 409


def test_body_compared_byte_for_byte(mock: Mock) -> None:
    """R-077: the same JSON written differently is a different body: 409."""
    _, key, _ = mock.agent_with_mandate()
    compact = b'{"amount":120.00,"currency":"USD","recipient":"vendor:acme_saas","category":"saas"}'
    spaced = b'{"amount": 120.00, "currency": "USD", "recipient": "vendor:acme_saas", "category": "saas"}'  # noqa: E501
    assert mock.post("/v1/authorizations", key=key, idem="k", raw=compact).status_code == 201
    assert mock.post("/v1/authorizations", key=key, idem="k", raw=spaced).status_code == 409


def test_key_is_tied_to_the_endpoint(mock: Mock) -> None:
    """R-078: an Idempotency-Key used on one endpoint never replays that result on another:
    the second call is 409, and the first call's effect stands"""
    agent, _ = mock.new_agent()
    assert mock.post(f"/v1/agents/{agent}/disable", idem="k-1").status_code == 200
    other = mock.post(f"/v1/agents/{agent}/enable", idem="k-1")
    assert other.status_code == 409
    assert mock.body(other)["error"]["code"] == "idempotency_conflict"
    replay = mock.post(f"/v1/agents/{agent}/disable", idem="k-1")
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert mock.body(mock.post(f"/v1/agents/{agent}/enable", idem="k-2"))["status"] == "active"
