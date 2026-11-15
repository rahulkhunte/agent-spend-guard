"""Webhook events: signed once, delivered as application/jwt, retried with the identical token."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from mock_api import webhooks
from tests.mock_api.conftest import START, Mock

ALL_DECISION_EVENTS = ["decision.review_pending", "decision.resolved", "mandate.revoked"]


def test_review_pending_delivered_as_jwt(mock: Mock, monkeypatch: pytest.MonkeyPatch) -> None:
    """R-130, R-135: a review fires decision.review_pending, POSTed as application/jwt."""
    mock.register_webhook(["decision.review_pending"])
    _, key, _ = mock.agent_with_mandate()
    decision = mock.review(key)
    (event,) = mock.delivered()
    assert event["type"] == "decision.review_pending"
    assert event["data"] == decision

    sent: dict[str, Any] = {}

    class Reply:
        status_code = 204

    def fake_post(url: str, **kwargs: Any) -> Reply:
        sent.update(url=url, **kwargs)
        return Reply()

    monkeypatch.setattr(webhooks.httpx, "post", fake_post)
    assert webhooks.http_sender("https://ops.example.com/hook", "a.b.c") == 204
    assert sent["headers"] == {"Content-Type": "application/jwt"}
    assert sent["content"] == "a.b.c"


def test_event_token_has_no_exp_or_nonce(mock: Mock) -> None:
    """R-131, R-104: an event token carries iss, jti, iat, type and data only: no exp, no nonce."""
    mock.register_webhook(["decision.review_pending"])
    _, key, _ = mock.agent_with_mandate()
    mock.review(key)
    (event,) = mock.delivered()
    assert set(event) == {"iss", "jti", "iat", "type", "data"}
    assert event["iss"] == "https://verdicts.agent-spend-guard.local"


def test_retries_resend_identical_token(mock: Mock) -> None:
    """R-132, R-134, R-141: failures retry after 1 s, then 2 s, with the identical token (same
    jti); a 2xx ends delivery."""
    mock.register_webhook(["decision.review_pending"])
    _, key, _ = mock.agent_with_mandate()
    mock.review(key)
    mock.sender.statuses = [500, 0, 200]

    mock.state.tick()  # attempt 1: 500
    mock.state.tick()  # not due yet
    assert len(mock.sender.calls) == 1
    mock.clock.advance(seconds=1)
    mock.state.tick()  # attempt 2: unreachable
    mock.clock.advance(seconds=1)
    mock.state.tick()  # not due: the next wait is 2 s
    assert len(mock.sender.calls) == 2
    mock.clock.advance(seconds=1)
    mock.state.tick()  # attempt 3: 200
    mock.clock.advance(hours=1)
    mock.state.tick()  # delivered: nothing more
    tokens = [token for _, token, _ in mock.sender.calls]
    assert len(tokens) == 3
    assert len(set(tokens)) == 1


def test_delivery_dropped_after_24_hours(mock: Mock) -> None:
    """R-133: an endpoint that never answers 2xx gets its last retry by 24 hours, then nothing."""
    mock.register_webhook(["decision.review_pending"])
    _, key, _ = mock.agent_with_mandate()
    mock.review(key)
    mock.sender.default_status = 503
    for _ in range(26 * 60):  # a pass every minute for 26 hours
        mock.state.tick()
        mock.clock.advance(minutes=1)
    times = [when for _, _, when in mock.sender.calls]
    assert times[-1] <= START + timedelta(hours=24)
    assert times[-1] > START + timedelta(hours=23)  # it kept retrying until near the end
    assert len(times) < 40  # with backoff, not once a minute


def test_resolved_on_deny_carries_review(mock: Mock) -> None:
    """R-136, R-137: denying a review fires decision.resolved carrying the review object."""
    mock.register_webhook(["decision.resolved"])
    _, key, _ = mock.agent_with_mandate()
    review = mock.review(key)["review"]
    mock.post(f"/v1/reviews/{review['review']}/deny")
    (event,) = mock.delivered()
    assert event["type"] == "decision.resolved"
    assert event["data"] == {**review, "status": "denied"}


def test_resolved_on_expiry(mock: Mock) -> None:
    """R-136, R-137: a review left for 24 hours expires and fires decision.resolved."""
    mock.register_webhook(["decision.resolved"])
    _, key, _ = mock.agent_with_mandate()
    review = mock.review(key)["review"]
    mock.clock.advance(hours=23)
    assert mock.delivered() == []
    mock.clock.advance(hours=1)
    (event,) = mock.delivered()
    assert event["data"] == {**review, "status": "expired"}
    mock.clock.advance(hours=1)
    assert len(mock.delivered()) == 1  # expired once, announced once


def test_resolved_on_approval(mock: Mock) -> None:
    """R-136, R-138: approval fires decision.resolved carrying the new allow decision."""
    mock.register_webhook(["decision.resolved"])
    _, key, _ = mock.agent_with_mandate()
    review_id = mock.review(key)["review"]["review"]
    approval = mock.body(mock.post(f"/v1/reviews/{review_id}/approve"))
    (event,) = mock.delivered()
    assert event["data"] == approval
    assert event["data"]["verdict"] == "allow"


def test_mandate_revoked_event(mock: Mock) -> None:
    """R-139: revoking a mandate fires mandate.revoked with the revoked mandate."""
    mock.register_webhook(["mandate.revoked"])
    agent, _ = mock.new_agent()
    mandate = mock.new_mandate(agent)
    revoked = mock.body(mock.post(f"/v1/mandates/{mandate['mandate']}/revoke"))
    (event,) = mock.delivered()
    assert event["type"] == "mandate.revoked"
    assert event["data"] == revoked


def test_only_subscribed_events_delivered(mock: Mock) -> None:
    """R-140: an endpoint gets only the event types it registered for."""
    mock.register_webhook(["mandate.revoked"], url="https://a.example.com/hook")
    mock.register_webhook(ALL_DECISION_EVENTS, url="https://b.example.com/hook")
    _, key, mandate = mock.agent_with_mandate()
    mock.review(key)
    mock.post(f"/v1/mandates/{mandate['mandate']}/revoke")
    mock.state.tick()
    by_url: dict[str, list[str]] = {}
    for url, token, _ in mock.sender.calls:
        by_url.setdefault(url, []).append(mock.claims(token)["type"])
    assert by_url["https://a.example.com/hook"] == ["mandate.revoked"]
    assert by_url["https://b.example.com/hook"] == ["decision.review_pending", "mandate.revoked"]


def test_http_localhost_endpoint_allowed(mock: Mock) -> None:
    """R-142: the mock accepts http://localhost endpoints (a mock-only allowance); other plain-HTTP
    URLs are refused."""
    ok = mock.post("/v1/webhooks", {"url": "http://localhost:9000/hook", "events": ["ping"]})
    assert ok.status_code == 201
    bad = mock.post("/v1/webhooks", {"url": "http://example.com/hook", "events": ["ping"]})
    assert bad.status_code == 400
    empty = mock.post("/v1/webhooks", {"url": "https://example.com/hook", "events": []})
    assert empty.status_code == 400
