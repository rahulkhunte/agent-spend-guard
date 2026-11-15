"""The order gates run in, and how several mandates combine into one verdict."""

from __future__ import annotations

from decimal import Decimal

from tests.mock_api.conftest import Mock


def test_limit_checked_before_velocity(mock: Mock) -> None:
    """R-033: amount limits come before velocity, so an over-limit request in a burst is
    deny_limit."""
    _, key, _ = mock.agent_with_mandate()
    for _ in range(10):
        mock.decide(key, "1")
    assert mock.decide(key, "720.00")["verdict"] == "deny_limit"
    assert mock.decide(key, "1")["verdict"] == "deny_velocity"


def test_revocation_checked_before_category(mock: Mock) -> None:
    """R-033: revocation comes before category, and category before amount."""
    _, key, mandate = mock.agent_with_mandate()
    assert mock.decide(key, "720.00", category="travel")["verdict"] == "deny_category"
    mock.post(f"/v1/mandates/{mandate['mandate']}/revoke")
    assert mock.decide(key, "720.00", category="travel")["verdict"] == "deny_revoked"


def test_first_allow_wins_across_mandates(mock: Mock) -> None:
    """R-034: with several mandates, the first allow wins, even from a newer mandate."""
    agent, key = mock.new_agent()
    mock.new_mandate(agent, categories=["travel"])
    saas = mock.new_mandate(agent, categories=["saas"])
    decision = mock.decide(key, "120.00", category="saas")
    assert decision["verdict"] == "allow"
    assert decision["mandate"] == saas["mandate"]


def test_review_beats_denials(mock: Mock) -> None:
    """R-034: with no allow, the first review wins over denials from older mandates."""
    agent, key = mock.new_agent()
    mock.new_mandate(agent, categories=["travel"])
    reviewing = mock.new_mandate(agent, review_above=Decimal("100"))
    decision = mock.decide(key, "150.00")
    assert decision["verdict"] == "review"
    assert decision["mandate"] == reviewing["mandate"]


def test_oldest_result_when_all_deny(mock: Mock) -> None:
    """R-034: when every mandate denies, the verdict is the oldest mandate's result."""
    agent, key = mock.new_agent()
    oldest = mock.new_mandate(
        agent,
        limits={"per_transaction": Decimal("100"), "currency": "USD"},
        review_above=None,
    )
    mock.new_mandate(agent, categories=["travel"])
    decision = mock.decide(key, "150.00")
    assert decision["verdict"] == "deny_limit"
    assert decision["mandate"] == oldest["mandate"]


def test_revoked_mandate_still_weighed(mock: Mock) -> None:
    """R-035: a revoked mandate stays in the evaluation; a newer active one can still allow."""
    agent, key, revoked = mock.agent_with_mandate()
    mock.post(f"/v1/mandates/{revoked['mandate']}/revoke")
    decision = mock.decide(key)
    assert decision["verdict"] == "deny_revoked"
    assert decision["mandate"] == revoked["mandate"]

    replacement = mock.new_mandate(agent)
    decision = mock.decide(key)
    assert decision["verdict"] == "allow"
    assert decision["mandate"] == replacement["mandate"]
