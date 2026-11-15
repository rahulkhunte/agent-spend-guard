"""Enforcement: one switch per environment, recorded on each decision. The mock blocks nothing."""

from __future__ import annotations

from tests.mock_api.conftest import Mock


def test_sandbox_defaults_to_enforce(mock: Mock) -> None:
    """R-060, R-063: a new sandbox starts in enforce; GET returns mode and since."""
    response = mock.get("/v1/enforcement")
    assert response.status_code == 200
    assert mock.body(response) == {"mode": "enforce", "since": "2026-10-27T12:00:00Z"}
    _, key, _ = mock.agent_with_mandate()
    assert mock.decide(key)["mode"] == "enforce"


def test_switch_recorded_on_next_decision(mock: Mock) -> None:
    """R-061: the switch applies from the next decision; the verdict itself doesn't change."""
    _, key, _ = mock.agent_with_mandate()
    mock.clock.advance(minutes=1)
    switched = mock.post("/v1/enforcement", {"mode": "observe"})
    assert switched.status_code == 200
    assert mock.body(switched) == {"mode": "observe", "since": "2026-10-27T12:01:00Z"}

    denied = mock.decide(key, "720.00")
    assert denied["mode"] == "observe"
    assert denied["verdict"] == "deny_limit"  # same verdict: the API blocks nothing either way

    mock.post("/v1/enforcement", {"mode": "enforce"})
    assert mock.decide(key, "720.00")["mode"] == "enforce"


def test_enforcement_needs_org_key_and_valid_mode(mock: Mock) -> None:
    """R-062: only `observe` or `enforce`, and only with an organization key."""
    _, key = mock.new_agent()
    assert mock.post("/v1/enforcement", {"mode": "observe"}, key=key).status_code == 403
    assert mock.post("/v1/enforcement", {"mode": "off"}).status_code == 400
    assert mock.post("/v1/enforcement", {"mode": "observe", "scope": "saas"}).status_code == 400
    assert mock.body(mock.get("/v1/enforcement"))["mode"] == "enforce"
