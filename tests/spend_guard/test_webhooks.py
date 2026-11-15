"""The webhook receiver, fed real events signed by the mock.

The mock's fake sender records each delivery; these tests hand the recorded token to
the receiver, as the HTTP POST would. The receiver re-reads objects with the org key.
"""

from __future__ import annotations

import sqlite3
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from spend_guard.client import SpendGuardClient
from spend_guard.models import Decision
from spend_guard.webhooks import WebhookReceiver, create_receiver_app
from tests.spend_guard.conftest import ORG_KEY, World, mock_keyset, unreachable_client

JWT = "application/jwt"


class Desk:
    """Where notifications for a person land in tests."""

    def __init__(self) -> None:
        self.messages: list[str] = []
        self.approvals: list[Decision] = []


def receiver_for(world: World, desk: Desk, **settings: Any) -> WebhookReceiver:
    client = SpendGuardClient(
        ORG_KEY, http=world.mock.client, clock=world.mock.clock, sleep=lambda _: None
    )
    options: dict[str, Any] = {
        "jwks": mock_keyset(world.mock),
        "client": client,
        "is_our_review": world.ledger.has_review,
        "notify": desk.messages.append,
        "on_approval": desk.approvals.append,
        "allow_sandbox": True,  # the mock is sandbox
        "clock": world.mock.clock,
    }
    options.update(settings)
    return WebhookReceiver(**options)


@pytest.fixture
def desk() -> Desk:
    return Desk()


@pytest.fixture
def receiver(world: World, desk: Desk) -> WebhookReceiver:
    world.mock.register_webhook(["decision.review_pending", "decision.resolved", "mandate.revoked"])
    return receiver_for(world, desk)


def deliveries(world: World) -> list[str]:
    """Run the mock's delivery pass; return every token sent so far, oldest first."""
    world.mock.state.tick()
    return [token for _, token, _ in world.mock.sender.calls]


def pending_review(world: World) -> str:
    """Make the gate hit a review; return the review_pending event token."""
    result = world.gate.pay(world.order("o-1", "340.00"))
    assert result.review is not None
    [token] = deliveries(world)
    return token


def sign_event(world: World, event_type: str, data: dict[str, Any], **claims: Any) -> str:
    """An event signed by the mock's key, for types the mock doesn't send."""
    body = {
        "iss": "https://verdicts.agent-spend-guard.local",
        "jti": f"evt_test_{event_type}",
        "iat": int(world.mock.clock.now().timestamp()),
        "type": event_type,
        "data": data,
        **claims,
    }
    return world.mock.state.signer.sign(body)


# A review reaches a person


def test_review_pending_notifies_a_human(
    world: World, receiver: WebhookReceiver, desk: Desk
) -> None:
    """R-230, R-227, R-221: decision.review_pending is verified, re-read with our key, and sent to
    a person with the review id, amount and recipient"""
    token = pending_review(world)
    assert receiver.handle(token.encode(), JWT) == (200, "review sent to a person")
    [message] = desk.messages
    [row] = world.ledger.attempts("o-1")
    assert row["review"] in message and "340 USD to vendor:acme_saas" in message


def test_notify_human_default_prints(capsys: pytest.CaptureFixture[str]) -> None:
    """R-230: the default notifier writes a clearly marked line a person will see"""
    from spend_guard.webhooks import notify_human

    notify_human("Review rev_1 needs a decision")
    assert "HUMAN ACTION NEEDED" in capsys.readouterr().err


def test_duplicate_delivery_acted_on_once(
    world: World, receiver: WebhookReceiver, desk: Desk
) -> None:
    """R-223: the same event (same jti) delivered twice is acknowledged, acted on once"""
    token = pending_review(world)
    receiver.handle(token.encode(), JWT)
    assert receiver.handle(token.encode(), JWT) == (200, "duplicate, already handled")
    assert len(desk.messages) == 1


def test_duplicate_makes_no_api_call(
    world: World, receiver: WebhookReceiver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-223: a delivery already handled is acknowledged without re-reading the object"""
    token = pending_review(world)
    receiver.handle(token.encode(), JWT)
    calls: list[str] = []
    monkeypatch.setattr(receiver.client, "get_decision", calls.append)
    receiver.handle(token.encode(), JWT)
    assert calls == []


def test_racing_duplicates_acted_on_once(
    world: World, receiver: WebhookReceiver, desk: Desk, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-223: two deliveries that both pass the "seen?" check still act once, because
    storing the event (jti primary key) is the atomic step"""
    token = pending_review(world)
    monkeypatch.setattr(receiver, "_seen", lambda jti: False)  # both got past the check
    assert receiver.handle(token.encode(), JWT)[1] == "review sent to a person"
    assert receiver.handle(token.encode(), JWT)[1] == "duplicate, already handled"
    assert len(desk.messages) == 1


def test_events_are_kept_append_only(world: World, receiver: WebhookReceiver) -> None:
    """R-231: every accepted event is stored with its raw token, and never changed"""
    token = pending_review(world)
    receiver.handle(token.encode(), JWT)
    [stored] = receiver.events()
    assert stored["token"] == token and stored["type"] == "decision.review_pending"
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        receiver._conn.execute("DELETE FROM events")


# Checks on the event itself


def test_wrong_content_type_rejected(world: World, receiver: WebhookReceiver) -> None:
    """R-220: the body must arrive as application/jwt"""
    token = pending_review(world)
    assert receiver.handle(token.encode(), "application/json")[0] == 400
    assert receiver.handle(token.encode(), "application/jwt; charset=utf-8")[0] == 200


def test_tampered_event_rejected(world: World, receiver: WebhookReceiver, desk: Desk) -> None:
    """R-221: an event whose signature doesn't verify is rejected and not acted on"""
    token = pending_review(world)
    tampered = token[:-6] + ("AAAAAA" if not token.endswith("AAAAAA") else "BBBBBB")
    assert receiver.handle(tampered.encode(), JWT)[0] == 400
    assert desk.messages == [] and receiver.events() == []


def test_verdict_token_is_not_an_event(world: World, receiver: WebhookReceiver) -> None:
    """R-222: a verdict token (no type, no data) is rejected by the event check"""
    world.gate.pay(world.order("o-1"))
    [row] = world.ledger.attempts("o-1")
    status, reason = receiver.handle(row["verdict_token"].encode(), JWT)
    assert status == 400 and "type, data" in reason


def test_sandbox_event_rejected_on_production_endpoint(world: World, desk: Desk) -> None:
    """R-224: a sandbox- kid is rejected unless the endpoint is configured for sandbox"""
    world.mock.register_webhook(["decision.review_pending"])
    production = receiver_for(world, desk, allow_sandbox=False)
    status, reason = production.handle(pending_review(world).encode(), JWT)
    assert status == 400 and "sandbox" in reason


def test_event_older_than_25_hours_rejected(world: World, receiver: WebhookReceiver) -> None:
    """R-225: an event exactly 25 hours old is accepted; one second older is rejected"""
    token = pending_review(world)
    world.mock.clock.advance(hours=25, seconds=1)
    status, reason = receiver.handle(token.encode(), JWT)
    assert status == 400 and "25 hours" in reason
    world.mock.clock.advance(seconds=-1)
    assert receiver.handle(token.encode(), JWT)[0] == 200


def test_event_from_the_future_rejected(world: World, receiver: WebhookReceiver) -> None:
    """R-226: an event iat more than 60 s ahead is rejected (it would dodge the age check)"""
    now = int(world.mock.clock.now().timestamp())
    assert receiver.handle(sign_event(world, "ping", {}, iat=now + 61).encode(), JWT)[0] == 400
    assert receiver.handle(sign_event(world, "ping", {}, iat=now + 60).encode(), JWT)[0] == 200


# Re-reading the object before acting


def test_object_not_found_with_our_key_is_ignored(
    world: World, receiver: WebhookReceiver, desk: Desk
) -> None:
    """R-227: a genuine event about an object our key can't read (another organization's)
    is acknowledged and ignored"""
    token = sign_event(world, "decision.review_pending", {"decision": "dec_elsewhere"})
    assert receiver.handle(token.encode(), JWT) == (200, "not one of our objects; ignored")
    assert desk.messages == []


def test_acts_on_the_fetched_object_not_the_event_copy(
    world: World, receiver: WebhookReceiver, desk: Desk
) -> None:
    """R-227: the notification uses what the API returns, not the event's own data"""
    pending_review(world)
    real = world.ledger.attempts("o-1")[0]["decision"]
    lying = {"decision": real, "request": {"amount": 1, "recipient": "vendor:evil"}}
    receiver.handle(sign_event(world, "decision.review_pending", lying).encode(), JWT)
    [message] = desk.messages
    assert "vendor:acme_saas" in message and "vendor:evil" not in message


def test_api_down_answers_503_and_retry_succeeds(
    world: World, receiver: WebhookReceiver, desk: Desk
) -> None:
    """R-229: if the object can't be re-read, answer non-2xx without recording, so the
    sender's retry of the identical token is processed"""
    token = pending_review(world)

    def down(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": {"code": "server_error", "message": "x",
                                                   "request_id": "req_1"}})  # fmt: skip

    working = receiver.client
    outage = httpx.Client(base_url="http://down.test", transport=httpx.MockTransport(down))
    receiver.client = SpendGuardClient(ORG_KEY, http=outage, sleep=lambda _: None)
    assert receiver.handle(token.encode(), JWT)[0] == 503
    assert receiver.events() == [] and desk.messages == []
    receiver.client = working
    assert receiver.handle(token.encode(), JWT)[0] == 200
    assert len(desk.messages) == 1


# decision.resolved, mandate.revoked, ping


def test_approval_event_is_read_back_and_handed_over(
    world: World, receiver: WebhookReceiver, desk: Desk
) -> None:
    """R-227, R-230: decision.resolved for an approval is re-read and handed to on_approval,
    which can pay it through the gate"""
    order = world.order("o-1", "340.00")
    pending = world.gate.pay(order)
    assert pending.review is not None
    world.mock.post(f"/v1/reviews/{pending.review}/approve")
    _, resolved = deliveries(world)
    assert receiver.handle(resolved.encode(), JWT) == (200, "approval received")
    [approval] = desk.approvals
    assert approval.supersedes == pending.decision
    assert world.gate.pay_approved(order, approval.decision).paid


def test_denied_review_acted_on_only_if_ours(
    world: World, receiver: WebhookReceiver, desk: Desk
) -> None:
    """R-228: a denied review (no endpoint to re-read) is acted on only if one of our own
    authorization responses returned its id"""
    pending = world.gate.pay(world.order("o-1", "340.00"))
    world.mock.post(f"/v1/reviews/{pending.review}/deny")
    _, resolved = deliveries(world)
    assert receiver.handle(resolved.encode(), JWT) == (200, "review denied")
    assert desk.messages == [f"Review {pending.review} was denied. Nothing will be paid."]

    stranger = sign_event(world, "decision.resolved", {"review": "rev_other", "status": "denied"})
    assert receiver.handle(stranger.encode(), JWT) == (200, "review is not one of ours; ignored")
    assert len(desk.messages) == 1


def test_mandate_revoked_notifies(world: World, receiver: WebhookReceiver, desk: Desk) -> None:
    """R-227: mandate.revoked is re-read with our key, then sent to a person"""
    world.mock.post(f"/v1/mandates/{world.mandate['mandate']}/revoke")
    [token] = deliveries(world)
    assert receiver.handle(token.encode(), JWT) == (200, "revocation sent to a person")
    assert world.mandate["mandate"] in desk.messages[0]


def test_ping_needs_no_action(world: World, receiver: WebhookReceiver, desk: Desk) -> None:
    """R-232: a ping is verified and acknowledged, and nothing else happens"""
    assert receiver.handle(sign_event(world, "ping", {}).encode(), JWT) == (200, "ping")
    assert desk.messages == []


# Over HTTP


def test_receiver_app_over_http(world: World, receiver: WebhookReceiver, desk: Desk) -> None:
    """R-220, R-229: the HTTP route answers 2xx to acknowledge and 400 to reject"""
    http = TestClient(create_receiver_app(receiver))
    token = pending_review(world)
    ok = http.post("/webhooks", content=token, headers={"Content-Type": JWT})
    bad = http.post("/webhooks", content="not.a.token", headers={"Content-Type": JWT})
    assert (ok.status_code, bad.status_code) == (200, 400)
    assert len(desk.messages) == 1


def test_unreachable_api_answers_503(world: World, receiver: WebhookReceiver, desk: Desk) -> None:
    """R-229: if the API can't be reached at all for the re-read, the answer is still 503
    with nothing recorded, so the sender retries"""
    token = pending_review(world)
    receiver.client = unreachable_client(ORG_KEY)
    assert receiver.handle(token.encode(), JWT)[0] == 503
    assert receiver.events() == [] and desk.messages == []
