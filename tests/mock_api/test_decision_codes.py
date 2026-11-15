"""One test per decision code. Each test uses a fresh agent,
because the engine weighs every mandate an agent has ever held."""

from __future__ import annotations

from decimal import Decimal

from tests.mock_api.conftest import Mock


def test_allow(mock: Mock) -> None:
    """R-022: a request inside the mandate is allowed under that mandate."""
    _, key, mandate = mock.agent_with_mandate()
    decision = mock.decide(key, "120.00")
    assert decision["verdict"] == "allow"
    assert decision["mandate"] == mandate["mandate"]
    assert decision["reason"] == f"within mandate {mandate['mandate']}"


def test_review(mock: Mock) -> None:
    """R-023, R-050: above review_above is `review`, with a pending review object."""
    _, key, _ = mock.agent_with_mandate()
    decision = mock.decide(key, "340.00")
    assert decision["verdict"] == "review"
    review = decision["review"]
    assert set(review) == {"review", "waits_for", "expires_at", "status"}
    assert review["review"].startswith("rev_")
    assert review["waits_for"] == "role:procurement_lead"
    assert review["expires_at"] == "2026-10-28T12:00:00Z"
    assert review["status"] == "pending"


def test_deny_limit_per_transaction(mock: Mock) -> None:
    """R-024: over per_transaction is deny_limit, with a reason naming both amounts."""
    _, key, _ = mock.agent_with_mandate()
    decision = mock.decide(key, "720.00")
    assert decision["verdict"] == "deny_limit"
    assert decision["reason"] == "amount 720.00 exceeds per_transaction limit 500.00"


def test_deny_limit_rolling_30_days(mock: Mock) -> None:
    """R-025: per_month counts allows under the mandate in the last 30 days, plus this request."""
    _, key, _ = mock.agent_with_mandate(
        limits={"per_transaction": Decimal("500"), "per_month": Decimal("300"), "currency": "USD"},
        review_above=None,
    )
    assert mock.decide(key, "200")["verdict"] == "allow"
    assert mock.decide(key, "100")["verdict"] == "allow"  # exactly at per_month: within it
    denied = mock.decide(key, "1")
    assert denied["verdict"] == "deny_limit"
    assert "per_month" in denied["reason"]
    assert mock.decide(key, "0.50")["verdict"] == "deny_limit"  # denials don't use up the limit

    mock.clock.advance(days=30)  # the first allows roll out of the window
    assert mock.decide(key, "300")["verdict"] == "allow"


def test_deny_velocity_on_11th_decision(mock: Mock) -> None:
    """R-026: ten decisions in 60 seconds are fine; the 11th is deny_velocity."""
    _, key, _ = mock.agent_with_mandate()
    for _ in range(10):
        assert mock.decide(key, "1")["verdict"] == "allow"
    decision = mock.decide(key, "1")
    assert decision["verdict"] == "deny_velocity"
    assert "10 decisions in the last 60 seconds" in decision["reason"]

    mock.clock.advance(seconds=60)
    assert mock.decide(key, "1")["verdict"] == "allow"


def test_velocity_ignores_errors_and_replays(mock: Mock) -> None:
    """R-027: rejected requests and idempotent replays create no decision, so they don't count."""
    _, key, _ = mock.agent_with_mandate()
    assert mock.authorize(key, "1", idem="first").status_code == 201
    for _ in range(8):
        mock.decide(key, "1")
    for _ in range(3):
        assert mock.authorize(key, "-1").status_code == 400
    for _ in range(2):
        replay = mock.authorize(key, "1", idem="first")
        assert replay.headers["Idempotency-Replayed"] == "true"
    assert mock.decide(key, "1")["verdict"] == "allow"  # the 10th decision
    assert mock.decide(key, "1")["verdict"] == "deny_velocity"  # the 11th


def test_deny_category(mock: Mock) -> None:
    """R-028: a category the mandate doesn't list is deny_category, and the reason names it."""
    _, key, _ = mock.agent_with_mandate()
    decision = mock.decide(key, "120.00", category="travel")
    assert decision["verdict"] == "deny_category"
    assert "travel" in decision["reason"]


def test_deny_expired(mock: Mock) -> None:
    """R-029, R-030: deny_expired from 00:00 UTC on the expires date (the stricter reading)."""
    _, key, _ = mock.agent_with_mandate(expires="2026-10-28")
    mock.clock.advance(hours=11, minutes=59, seconds=59)  # 2026-10-27T23:59:59Z
    assert mock.decide(key)["verdict"] == "allow"
    mock.clock.advance(seconds=1)  # 2026-10-28T00:00:00Z
    decision = mock.decide(key)
    assert decision["verdict"] == "deny_expired"
    assert "2026-10-28" in decision["reason"]


def test_deny_revoked(mock: Mock) -> None:
    """R-031: after revocation, the next request is deny_revoked."""
    _, key, mandate = mock.agent_with_mandate()
    assert mock.decide(key)["verdict"] == "allow"
    assert mock.post(f"/v1/mandates/{mandate['mandate']}/revoke").status_code == 200
    decision = mock.decide(key)
    assert decision["verdict"] == "deny_revoked"
    assert decision["mandate"] == mandate["mandate"]


def test_deny_no_mandate_without_mandate(mock: Mock) -> None:
    """R-020, R-032: an agent with no mandate gets deny_no_mandate, with no `mandate` field."""
    _, key = mock.new_agent()
    decision = mock.decide(key)
    assert decision["verdict"] == "deny_no_mandate"
    assert "mandate" not in decision
    assert "mandate" not in mock.claims(decision["verdict_token"])


def test_deny_no_mandate_wrong_currency_case(mock: Mock) -> None:
    """R-002: currency is matched exactly and case-sensitively; `usd` is not `USD`."""
    _, key, _ = mock.agent_with_mandate()
    assert mock.decide(key, currency="usd")["verdict"] == "deny_no_mandate"
    assert mock.decide(key, currency="EUR")["verdict"] == "deny_no_mandate"
    assert mock.decide(key, currency="USD")["verdict"] == "allow"


def test_deny_no_mandate_disabled_agent(mock: Mock) -> None:
    """R-032, R-048: a disabled agent's mandates stop matching: deny_no_mandate."""
    agent, key, _ = mock.agent_with_mandate()
    response = mock.post(f"/v1/agents/{agent}/disable")
    assert response.status_code == 200
    assert mock.body(response)["status"] == "disabled"
    decision = mock.decide(key)
    assert decision["verdict"] == "deny_no_mandate"
    assert "mandate" not in decision


def test_enable_restores_agent(mock: Mock) -> None:
    """R-049: /enable reverses a disable."""
    agent, key, _ = mock.agent_with_mandate()
    mock.post(f"/v1/agents/{agent}/disable")
    assert mock.decide(key)["verdict"] == "deny_no_mandate"
    response = mock.post(f"/v1/agents/{agent}/enable")
    assert mock.body(response)["status"] == "active"
    assert mock.decide(key)["verdict"] == "allow"


def test_limits_are_strict_at_the_boundary(mock: Mock) -> None:
    """R-023, R-024: "above" and "exceeds" are strict: an amount equal to a limit is not over it."""
    _, key, _ = mock.agent_with_mandate()
    assert mock.decide(key, "250.00")["verdict"] == "allow"  # equal to review_above
    assert mock.decide(key, "250.01")["verdict"] == "review"
    assert mock.decide(key, "500.00")["verdict"] == "review"  # equal to per_transaction
    assert mock.decide(key, "500.01")["verdict"] == "deny_limit"


def test_review_approval_counts_toward_velocity(mock: Mock) -> None:
    """R-027: a review approval is a decision for that agent, so it counts: a review, eight
    more decisions and the approval make ten, and the next request is deny_velocity"""
    _, key, _ = mock.agent_with_mandate()
    review_id = mock.review(key)["review"]["review"]
    for _ in range(8):
        mock.decide(key, "1")
    assert mock.post(f"/v1/reviews/{review_id}/approve").status_code == 201
    assert mock.decide(key, "1")["verdict"] == "deny_velocity"
