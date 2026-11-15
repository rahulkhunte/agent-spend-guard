"""The HTTP contract: statuses, envelopes, headers, validation, keys and ids."""

from __future__ import annotations

import re
from decimal import Decimal

from tests.mock_api.conftest import ORG_KEY, Mock


def test_denial_is_201(mock: Mock) -> None:
    """R-001: every verdict, denials included, is HTTP 201."""
    _, key, _ = mock.agent_with_mandate()
    for amount, category in (("720.00", "saas"), ("10", "travel"), ("340", "saas")):
        assert mock.authorize(key, amount, category=category).status_code == 201
    _, bare_key = mock.new_agent()
    assert mock.authorize(bare_key).status_code == 201  # deny_no_mandate


def test_decision_shape(mock: Mock) -> None:
    """R-021: every decision has the required fields; only an allow has expires_at, five minutes
    after issue."""
    _, key, _ = mock.agent_with_mandate()
    allow = mock.decide(key)
    required = {"decision", "request", "verdict", "reason", "policy_version", "nonce", "mode"}
    assert required | {"issued_at", "verdict_token", "mandate"} <= set(allow)
    assert allow["issued_at"] == "2026-10-27T12:00:00Z"
    assert allow["expires_at"] == "2026-10-27T12:05:00Z"
    for amount in ("720.00", "340.00"):
        assert "expires_at" not in mock.decide(key, amount)


def test_request_id_on_every_response(mock: Mock) -> None:
    """R-081: X-Request-Id on success and error alike; errors repeat it in the body."""
    _, key, _ = mock.agent_with_mandate()
    responses = [
        mock.authorize(key),
        mock.authorize(key, "-1"),
        mock.authorize(None),  # type: ignore[arg-type]
        mock.get("/v1/decisions/dec_missing"),
        mock.client.get("/.well-known/jwks.json"),
    ]
    for response in responses:
        assert re.fullmatch(r"req_[0-9a-f]{32}", response.headers["X-Request-Id"])
        if response.status_code >= 400:
            body = mock.body(response)
            assert body["error"]["request_id"] == response.headers["X-Request-Id"]


def test_error_envelope(mock: Mock) -> None:
    """R-080: errors are {"error": {"code", "message", "request_id"}}."""
    _, key, _ = mock.agent_with_mandate()
    body = mock.body(mock.authorize(key, "-1"))
    assert set(body) == {"error"}
    assert set(body["error"]) == {"code", "message", "request_id"}
    assert body["error"]["code"] == "invalid_request"


def test_missing_key_is_401_on_any_path(mock: Mock) -> None:
    """R-082, R-089: no key or an unknown key is 401 on any path, without RateLimit headers."""
    for path in ("/v1/authorizations", "/v1/does-not-exist", "/v1/reviews", "/v1", "/nothing"):
        for key in (None, "sk_sandbox_" + "1" * 32):
            response = mock.post(path, {}, key=key)
            assert response.status_code == 401, path
            assert mock.body(response)["error"]["code"] == "unauthorized"
            assert "RateLimit-Limit" not in response.headers


def test_agent_key_on_org_endpoint_is_403(mock: Mock) -> None:
    """R-083: an agent key on an organization endpoint is 403 and names the key class."""
    agent, key = mock.new_agent()
    for response in (
        mock.post("/v1/mandates", {"agent": agent}, key=key),
        mock.post(f"/v1/agents/{agent}/disable", key=key),
        mock.get("/v1/enforcement", key=key),
        mock.get("/v1/exports/records", key=key, **{"from": "2026-10-01", "to": "2026-11-01"}),
    ):
        assert response.status_code == 403
        error = mock.body(response)["error"]
        assert error["code"] == "forbidden"
        assert error["message"] == "This endpoint needs an organization key"


def test_other_agents_decision_is_404(mock: Mock) -> None:
    """R-084, R-120: another agent's decision is reported as absent, not forbidden."""
    _, key_a, _ = mock.agent_with_mandate()
    _, key_b, _ = mock.agent_with_mandate()
    decision = mock.decide(key_a)
    response = mock.get(f"/v1/decisions/{decision['decision']}", key=key_b)
    assert response.status_code == 404
    assert mock.body(response)["error"]["code"] == "not_found"


def test_get_decision(mock: Mock) -> None:
    """R-120, R-126: the decision is readable as soon as it is returned; an agent reads its own,
    the org reads every decision, unknown ids are 404."""
    _, key, _ = mock.agent_with_mandate()
    decision = mock.decide(key)
    path = f"/v1/decisions/{decision['decision']}"
    assert mock.body(mock.get(path, key=key)) == decision
    assert mock.body(mock.get(path)) == decision
    assert mock.get("/v1/decisions/dec_0000").status_code == 404


def test_unknown_field_is_400(mock: Mock) -> None:
    """R-007: an unknown field or a missing field is 400 invalid_request."""
    _, key, _ = mock.agent_with_mandate()
    response = mock.authorize(key, tip=Decimal("5"))
    assert response.status_code == 400
    assert mock.body(response)["error"]["message"] == "unknown field: tip"
    missing = mock.post(
        "/v1/authorizations",
        {"amount": Decimal("1"), "recipient": "vendor:x", "category": "saas"},
        key=key,
    )
    assert missing.status_code == 400
    assert mock.body(missing)["error"]["message"] == "currency is required"


def test_invalid_protocol_is_400(mock: Mock) -> None:
    """R-004: protocol must be x402, mpp, acp, ap2 or card; it is not echoed back."""
    _, key, _ = mock.agent_with_mandate()
    assert mock.authorize(key, protocol="paypal").status_code == 400
    for protocol in ("x402", "mpp", "acp", "ap2", "card"):
        decision = mock.decide(key, protocol=protocol)
        assert "protocol" not in decision and "protocol" not in decision["request"]


def test_field_length_limits(mock: Mock) -> None:
    """R-003: recipient up to 1,024 characters; currency and category up to 128."""
    _, key, _ = mock.agent_with_mandate()
    assert mock.authorize(key, recipient="v" * 1024).status_code == 201
    assert mock.authorize(key, recipient="v" * 1025).status_code == 400
    assert mock.authorize(key, currency="C" * 128).status_code == 201
    assert mock.authorize(key, currency="C" * 129).status_code == 400
    assert mock.authorize(key, category="c" * 129).status_code == 400


def test_metadata_limits(mock: Mock) -> None:
    """R-005, R-006: up to 20 string keys, values up to 500 characters, echoed back unread."""
    _, key, _ = mock.agent_with_mandate()
    twenty = {f"k{i}": "v" for i in range(20)}
    assert mock.decide(key, metadata=twenty)["metadata"] == twenty
    assert mock.authorize(key, metadata={**twenty, "k20": "v"}).status_code == 400
    assert mock.authorize(key, metadata={"note": "x" * 500}).status_code == 201
    assert mock.authorize(key, metadata={"note": "x" * 501}).status_code == 400
    assert mock.authorize(key, metadata={"count": Decimal("3")}).status_code == 400


def test_body_over_64kb_is_400(mock: Mock) -> None:
    """R-008, R-090: a body over 64 KB is refused before parsing, with 400 invalid_request."""
    _, key, _ = mock.agent_with_mandate()
    oversized = b'{"pad": "' + b"x" * (64 * 1024) + b'"}'
    response = mock.post("/v1/authorizations", key=key, raw=oversized)
    assert response.status_code == 400
    assert mock.body(response)["error"]["message"] == "request body is over 64 KB"


def test_unsupported_method_is_400(mock: Mock) -> None:
    """R-085: an unsupported method is 400 (not 405) with no Allow header."""
    agent, _ = mock.new_agent()
    mandate = mock.new_mandate(agent)
    path = f"/v1/mandates/{mandate['mandate']}"
    response = mock.client.delete(path, headers={"Authorization": f"Bearer {ORG_KEY}"})
    assert response.status_code == 400
    assert mock.body(response)["error"]["message"] == f"DELETE is not supported on {path}"
    assert "Allow" not in response.headers


def test_rate_limit_headers(mock: Mock) -> None:
    """R-087: every authenticated response, errors included, carries RateLimit-* headers."""
    _, key, _ = mock.agent_with_mandate()
    for response in (mock.authorize(key), mock.authorize(key, "-1")):
        assert response.headers["RateLimit-Limit"] == "600"
        assert int(response.headers["RateLimit-Remaining"]) < 600
        assert 0 < int(response.headers["RateLimit-Reset"]) <= 60


def test_rate_limit_is_per_key_sliding_window(make_mock) -> None:  # type: ignore[no-untyped-def]
    """R-086: the limit is per key over a sliding 60 seconds; another key is unaffected."""
    mock = make_mock(rate_limit=3)
    _, key = mock.new_agent()  # one org request so far
    for _ in range(2):
        assert mock.get("/v1/enforcement").status_code == 200
    limited = mock.get("/v1/enforcement")
    assert limited.status_code == 429
    assert mock.body(limited)["error"]["code"] == "rate_limited"
    assert int(limited.headers["Retry-After"]) >= 1
    assert mock.authorize(key).status_code == 201  # the agent key has its own window
    mock.clock.advance(seconds=60)
    assert mock.get("/v1/enforcement").status_code == 200


def test_429_burst_has_retry_after(mock: Mock) -> None:
    """R-088: a 429 carries Retry-After, in seconds."""
    _, key, _ = mock.agent_with_mandate()
    mock.post("/_mock/faults", {"rate_limit_burst": 1, "retry_after_seconds": 2})
    response = mock.authorize(key)
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "2"
    assert mock.body(response)["error"]["code"] == "rate_limited"
    assert mock.authorize(key).status_code == 201


def test_org_key_names_agent(mock: Mock) -> None:
    """R-009: an organization key must name the agent, and the agent must exist."""
    agent, _ = mock.new_agent()
    mock.new_mandate(agent)
    body = {"amount": Decimal("10"), "currency": "USD", "recipient": "vendor:x", "category": "saas"}
    assert mock.post("/v1/authorizations", body).status_code == 400
    assert mock.post("/v1/authorizations", {**body, "agent": "agt_nobody"}).status_code == 400
    response = mock.post("/v1/authorizations", {**body, "agent": agent})
    assert response.status_code == 201
    assert mock.body(response)["request"]["agent"] == agent


def test_agent_key_ignores_body_agent(mock: Mock) -> None:
    """R-009: with an agent key, the agent comes from the key; a body `agent` is ignored."""
    agent_a, key_a, _ = mock.agent_with_mandate()
    agent_b, _, _ = mock.agent_with_mandate()
    decision = mock.decide(key_a, agent=agent_b)
    assert decision["request"]["agent"] == agent_a


def test_amount_must_be_positive_number(mock: Mock) -> None:
    """R-010: amount must be a positive JSON number: not a string, bool, zero, negative or NaN."""
    _, key, _ = mock.agent_with_mandate()
    base = {"currency": "USD", "recipient": "vendor:x", "category": "saas"}
    for bad in ("120.00", True, Decimal("0"), Decimal("-5"), None):
        response = mock.post("/v1/authorizations", {**base, "amount": bad}, key=key)
        assert response.status_code == 400, bad
    nan = b'{"amount": NaN, "currency": "USD", "recipient": "vendor:x", "category": "saas"}'
    assert mock.post("/v1/authorizations", key=key, raw=nan).status_code == 400
    assert mock.post("/v1/authorizations", {**base, "amount": 7}, key=key).status_code == 201


def test_object_id_prefixes(mock: Mock) -> None:
    """R-110: objects carry the spec's id prefixes."""
    mock.register_webhook(["decision.review_pending"])
    agent, key, mandate = mock.agent_with_mandate()
    decision = mock.review(key)
    assert agent.startswith("agt_")
    assert mandate["mandate"].startswith("mnd_")
    assert decision["decision"].startswith("dec_")
    assert decision["nonce"].startswith("n_")
    assert decision["review"]["review"].startswith("rev_")
    assert decision["policy_version"].startswith("pol_")
    webhook = mock.body(
        mock.post("/v1/webhooks", {"url": "https://ops.example.com/x", "events": ["ping"]})
    )
    assert webhook["webhook"].startswith("whk_")
    assert mock.delivered()[0]["jti"].startswith("evt_")


def test_policy_version_from_org_date(mock: Mock) -> None:
    """R-111: policy_version is a per-organization label from its creation date; new mandates
    don't change it."""
    _, key, _ = mock.agent_with_mandate()
    assert mock.decide(key)["policy_version"] == "pol_2026-10-27.1"
    mock.clock.advance(days=3)
    _, other_key, _ = mock.agent_with_mandate()
    assert mock.decide(other_key)["policy_version"] == "pol_2026-10-27.1"


def test_agent_key_shown_once(mock: Mock) -> None:
    """R-047: the agent key is in the create response and nowhere after."""
    response = mock.post("/v1/agents", {"name": "procurement_01"})
    created = mock.body(response)
    assert re.fullmatch(r"ak_sandbox_[0-9a-f]{32}", created["agent_key"])
    later = mock.body(mock.post("/v1/agents/agt_procurement_01/disable"))
    assert "agent_key" not in later
    assert created["agent_key"] not in response.headers.values()


def test_agent_name_rules(mock: Mock) -> None:
    """R-045, R-046: a lowercase slug becomes `agt_<name>`; other names and taken names are 400."""
    response = mock.post("/v1/agents", {"name": "procurement_01"})
    assert response.status_code == 201
    created = mock.body(response)
    assert created["agent"] == "agt_procurement_01"
    assert created["status"] == "active"
    for bad in ("Procurement", "has space", "", "-leading"):
        assert mock.post("/v1/agents", {"name": bad}).status_code == 400, bad
    taken = mock.post("/v1/agents", {"name": "procurement_01"})
    assert taken.status_code == 400
    assert "already taken" in mock.body(taken)["error"]["message"]


def test_mandate_create_response(mock: Mock) -> None:
    """R-040: the response is the mandate as sent, plus its `mnd_` id and status active."""
    agent, _ = mock.new_agent()
    mandate = mock.new_mandate(agent)
    assert mandate["mandate"].startswith("mnd_")
    assert mandate["status"] == "active"
    assert mandate["principal"] == "role:procurement_lead"
    assert mandate["agent"] == agent
    assert mandate["limits"] == {
        "per_transaction": Decimal("500"),
        "per_month": Decimal("5000"),
        "currency": "USD",
    }
    assert mandate["categories"] == ["saas"]
    assert mandate["review_above"] == Decimal("250")
    assert mandate["expires"] == "2026-12-01"
    assert mock.body(mock.get(f"/v1/mandates/{mandate['mandate']}")) == mandate


def test_mandate_revoke_response(mock: Mock) -> None:
    """R-041: revoke returns the mandate with status revoked and revoked_at set."""
    agent, _ = mock.new_agent()
    mandate = mock.new_mandate(agent)
    mock.clock.advance(minutes=5)
    revoked = mock.body(mock.post(f"/v1/mandates/{mandate['mandate']}/revoke"))
    assert revoked["status"] == "revoked"
    assert revoked["revoked_at"] == "2026-10-27T12:05:00Z"
    assert {k: v for k, v in revoked.items() if k not in ("status", "revoked_at")} == {
        k: v for k, v in mandate.items() if k != "status"
    }


def test_revoke_twice_is_400(mock: Mock) -> None:
    """R-042: revoking an already-revoked mandate is 400."""
    agent, _ = mock.new_agent()
    mandate = mock.new_mandate(agent)
    assert mock.post(f"/v1/mandates/{mandate['mandate']}/revoke").status_code == 200
    assert mock.post(f"/v1/mandates/{mandate['mandate']}/revoke").status_code == 400


def test_mandate_for_unknown_agent_is_400(mock: Mock) -> None:
    """R-043: a mandate naming an agent that doesn't exist is 400."""
    response = mock.post(
        "/v1/mandates",
        {
            "principal": "role:x",
            "agent": "agt_nobody",
            "limits": {"per_transaction": Decimal("1"), "currency": "USD"},
            "categories": ["saas"],
            "expires": "2026-12-01",
        },
    )
    assert response.status_code == 400
    assert mock.body(response)["error"]["message"] == "unknown agent agt_nobody"


def test_escrow_required_above_stored_not_enforced(mock: Mock) -> None:
    """R-044: escrow.required_above round-trips but never changes a verdict."""
    _, key, mandate = mock.agent_with_mandate(
        escrow={"required_above": "100 USD"}, review_above=None
    )
    assert mandate["escrow"] == {"required_above": "100 USD"}
    assert mock.decide(key, "400.00")["verdict"] == "allow"


def test_key_set_needs_no_key(mock: Mock) -> None:
    """R-082: the public key set is the one path that answers without a key"""
    assert mock.get("/.well-known/jwks.json", key=None).status_code == 200


def test_crash_inside_an_endpoint_still_uses_the_envelope(mock: Mock, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """R-091: an unexpected failure inside the mock answers 500 server_error in the error
    envelope, with an X-Request-Id, and says nothing about the cause"""

    def broken() -> None:
        raise RuntimeError("database on fire")

    monkeypatch.setattr(mock.state.store, "mode", broken)
    response = mock.get("/v1/enforcement")
    error = mock.body(response)["error"]
    assert response.status_code == 500 and error["code"] == "server_error"
    assert error["request_id"] == response.headers["X-Request-Id"]
    assert "fire" not in response.text


def test_deeply_nested_body_is_400(mock: Mock) -> None:
    """R-091: a body nested too deeply to parse is invalid JSON: 400, not a crash"""
    _, key, _ = mock.agent_with_mandate()
    response = mock.post("/v1/authorizations", key=key, raw=b"[" * 60_000)
    assert response.status_code == 400
    assert mock.body(response)["error"]["code"] == "invalid_request"


def test_mandate_expires_must_be_yyyy_mm_dd(mock: Mock) -> None:
    """R-064: `expires` is a date written YYYY-MM-DD; other spellings of a date are 400"""
    agent, _ = mock.new_agent()
    for bad in ("20261201", "2026-12-1", "2026-12-01T00:00:00Z"):
        body = {
            "principal": "role:procurement_lead",
            "agent": agent,
            "limits": {
                "per_transaction": Decimal("500"),
                "per_month": Decimal("5000"),
                "currency": "USD",
            },
            "categories": ["saas"],
            "expires": bad,
        }
        assert mock.post("/v1/mandates", body).status_code == 400, bad
