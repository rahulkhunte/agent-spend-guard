"""PaymentGate against the in-process mock: what gets paid, what doesn't, and why."""

from __future__ import annotations

import logging
import sqlite3
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from decimal import Decimal
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from spend_guard.client import SpendGuardClient
from spend_guard.gate import PaymentGate
from spend_guard.ledger import Ledger
from spend_guard.models import Decision, Order, PaymentStatus
from spend_guard.provider import MockProvider
from tests.spend_guard.conftest import VENDOR, World, unreachable_client


def set_mode(world: World, mode: str) -> None:
    response = world.mock.post("/v1/enforcement", {"mode": mode})
    assert response.status_code == 200, response.text


def approve(world: World, review: str) -> str:
    response = world.mock.post(f"/v1/reviews/{review}/approve")
    assert response.status_code == 201, response.text
    return world.mock.body(response)["decision"]


def rewrite_decisions(world: World, monkeypatch: pytest.MonkeyPatch, **update: Any) -> None:
    """Make the client return each real decision with some fields changed."""
    real = world.client.authorize

    def authorize(**kwargs: Any) -> Decision:
        decision = real(**kwargs)
        changes = {name: fn(decision) if callable(fn) else fn for name, fn in update.items()}
        return decision.model_copy(update=changes)

    monkeypatch.setattr(world.client, "authorize", authorize)


# Allow, and what is stored about it


def test_allow_pays_once_and_links_the_decision(world: World) -> None:
    """R-161, R-168, R-178: an allow is verified, paid once, and the dec_ id and raw token
    are stored against the order"""
    result = world.gate.pay(world.order("o-1"))
    assert result.status is PaymentStatus.PAID and result.verdict == "allow"
    assert world.verifier.calls == 1
    [payment] = world.provider.payments()
    assert payment.reference == result.decision and payment.amount == Decimal("120.00")
    [attempt] = world.ledger.attempts("o-1")
    assert attempt["decision"] == result.decision and attempt["request_id"] == result.request_id
    assert attempt["verdict_token"].count(".") == 2
    assert "verdict_token" not in result.model_dump()


def test_reason_is_returned_exactly(world: World) -> None:
    """R-158: the gate passes the API's reason through unchanged"""
    result = world.gate.pay(world.order("o-1", "720.00"))
    [record] = world.decisions_for("o-1")
    assert result.reason == record["reason"]


# Enforce mode: only allow pays


@pytest.mark.parametrize(
    ("amount", "fields", "verdict"),
    [
        ("720.00", {}, "deny_limit"),
        ("120.00", {"category": "travel"}, "deny_category"),
        ("120.00", {"currency": "usd"}, "deny_no_mandate"),
        ("340.00", {}, "review"),
    ],
)
def test_enforce_pays_only_on_allow(
    world: World, amount: str, fields: dict[str, Any], verdict: str
) -> None:
    """R-161: in enforce mode, every verdict other than allow stops the payment"""
    result = world.gate.pay(world.order("o-1", amount, **fields))
    assert result.verdict == verdict and result.mode == "enforce"
    assert not result.paid and world.provider.payments() == []


def test_revoked_mandate_is_denied(world: World) -> None:
    """R-161: deny_revoked stops the payment"""
    assert world.mock.post(f"/v1/mandates/{world.mandate['mandate']}/revoke").status_code == 200
    result = world.gate.pay(world.order("o-1"))
    assert (result.status, result.verdict) == (PaymentStatus.DENIED, "deny_revoked")
    assert world.provider.payments() == []


def test_review_is_pending_not_paid(world: World) -> None:
    """R-164: review returns pending with the review id and expiry, and pays nothing"""
    result = world.gate.pay(world.order("o-1", "340.00"))
    assert result.status is PaymentStatus.PENDING_REVIEW
    assert result.review is not None and result.review.startswith("rev_")
    assert result.review_expires_at is not None
    assert world.provider.payments() == []


def test_pay_after_approval(world: World) -> None:
    """R-176: after a person approves, the new allow (supersedes = the review) is paid once"""
    order = world.order("o-1", "340.00")
    pending = world.gate.pay(order)
    assert pending.review is not None
    approval = approve(world, pending.review)
    result = world.gate.pay_approved(order, approval)
    assert result.status is PaymentStatus.PAID and result.decision == approval
    assert [p.reference for p in world.provider.payments()] == [approval]
    assert world.gate.pay_approved(order, approval).status is PaymentStatus.ALREADY_PAID
    assert len(world.provider.payments()) == 1


def test_approval_for_another_review_is_blocked(world: World) -> None:
    """R-176: an approval that supersedes a different review does not pay this order"""
    order_a, order_b = world.order("o-a", "340.00"), world.order("o-b", "341.00")
    world.gate.pay(order_a)
    pending_b = world.gate.pay(order_b)
    assert pending_b.review is not None
    approval_b = approve(world, pending_b.review)
    result = world.gate.pay_approved(order_a, approval_b)
    assert result.status is PaymentStatus.BLOCKED and "does not supersede" in result.detail
    unreviewed = world.gate.pay_approved(world.order("o-c"), approval_b)
    assert unreviewed.status is PaymentStatus.BLOCKED
    assert world.provider.payments() == []


# Unknown verdicts and modes


@pytest.mark.parametrize("forced", ["deny_future_rule", "Allow", "allow "])
def test_unknown_verdict_is_denial(world: World, forced: str) -> None:
    """R-155: a verdict the gate doesn't recognise, signed and returned as 201, is a denial"""
    world.set_faults(forced_verdict=forced)
    result = world.gate.pay(world.order("o-1"))
    assert result.verdict == forced
    assert result.status is PaymentStatus.DENIED and "unrecognized verdict" in result.detail
    assert world.provider.payments() == [] and world.verifier.calls == 0


def test_unknown_mode_treated_as_enforce(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    """R-174: a mode the gate doesn't know is treated as enforce"""
    rewrite_decisions(world, monkeypatch, mode="shadow")
    result = world.gate.pay(world.order("o-1", "720.00"))
    assert (result.status, result.mode) == (PaymentStatus.DENIED, "shadow")
    assert world.provider.payments() == []


# Observe mode


def test_observe_mode_pays_and_records_would_have_blocked(world: World) -> None:
    """R-163: in observe mode a denial is paid, and the record says enforce would have blocked"""
    set_mode(world, "observe")
    denied = world.gate.pay(world.order("o-1", "720.00"))
    assert (denied.status, denied.verdict, denied.mode) == (
        PaymentStatus.PAID,
        "deny_limit",
        "observe",
    )
    assert denied.would_have_blocked
    allowed = world.gate.pay(world.order("o-2"))
    assert allowed.paid and not allowed.would_have_blocked
    rows = world.ledger.attempts()
    assert [row["would_have_blocked"] for row in rows] == [1, 0]
    assert len(world.provider.payments()) == 2


def test_observe_mode_review_is_paid(world: World) -> None:
    """R-163: observe mode lets a review through too, recorded as would-have-blocked"""
    set_mode(world, "observe")
    result = world.gate.pay(world.order("o-1", "340.00"))
    assert result.paid and result.verdict == "review" and result.would_have_blocked


def test_mode_switch_takes_effect_on_next_payment(world: World) -> None:
    """R-162: the gate reads mode from each decision, so a switch applies on the next payment"""
    set_mode(world, "observe")
    assert world.gate.pay(world.order("o-1", "720.00")).paid
    set_mode(world, "enforce")
    result = world.gate.pay(world.order("o-2", "720.00"))
    assert result.status is PaymentStatus.DENIED and result.mode == "enforce"
    assert len(world.provider.payments()) == 1


# The integration's own checks


@pytest.mark.parametrize("mode", ["enforce", "observe"])
@pytest.mark.parametrize(("amount", "verdict"), [("120.00", "allow"), ("340.00", "review")])
def test_recipient_not_on_allowlist_is_blocked(
    world: World, mode: str, amount: str, verdict: str
) -> None:
    """R-165, R-175, R-179: a recipient off the allowlist is blocked whatever the verdict, in
    either mode; the attempt is in the decision log and the block in the ledger"""
    set_mode(world, mode)
    order = world.order("o-1", amount, recipient="vendor:new")
    result = world.gate.pay(order)
    assert (result.status, result.verdict) == (PaymentStatus.BLOCKED, verdict)
    assert "allowlist" in result.detail
    [record] = world.decisions_for("o-1")
    [row] = world.ledger.attempts("o-1")
    assert record["decision"] == result.decision == row["decision"]
    assert row["status"] == "blocked" and row["verdict_token"] == record["verdict_token"]
    assert world.provider.payments() == [] and world.verifier.calls == 0
    if result.review is not None:  # a person may still approve it; the gate still won't pay
        approval = approve(world, result.review)
        assert world.gate.pay_approved(order, approval).status is PaymentStatus.BLOCKED
        assert world.provider.payments() == []


@pytest.mark.parametrize("mode", ["enforce", "observe"])
def test_tampered_token_blocks_payment(
    world: World, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    """R-166, R-175: an allow whose token fails verification is never paid, in either mode"""
    set_mode(world, mode)
    rewrite_decisions(world, monkeypatch, verdict_token=lambda d: d.verdict_token[:-6] + "AAAAAA")
    result = world.gate.pay(world.order("o-1"))
    assert result.status is PaymentStatus.BLOCKED and "failed verification" in result.detail
    assert world.provider.payments() == []


def test_token_for_a_different_amount_blocks_payment(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-166: a valid allow for a different deal is not accepted for this order"""
    other = world.client.authorize(
        amount=Decimal("10.00"), currency="USD", recipient=VENDOR, category="saas",
        idempotency_key="someone-else",
    )  # fmt: skip
    rewrite_decisions(world, monkeypatch, verdict_token=other.verdict_token)
    result = world.gate.pay(world.order("o-1"))
    assert result.status is PaymentStatus.BLOCKED and world.provider.payments() == []


# Fail closed


def test_outage_fails_closed(world: World) -> None:
    """R-160, R-169: a 5xx outage means no verdict, so no payment; the req_ id is stored"""
    world.set_faults(error_rate=1.0)
    result = world.gate.pay(world.order("o-1"))
    assert result.status is PaymentStatus.NO_VERDICT and result.decision is None
    assert result.request_id is not None and result.request_id.startswith("req_")
    assert world.ledger.attempts("o-1")[0]["request_id"] == result.request_id
    assert world.provider.payments() == [] and world.decisions_for("o-1") == []


def test_timeouts_fail_closed(world: World) -> None:
    """R-160: timeouts on every attempt mean no verdict, so no payment"""

    def hang(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("no answer", request=request)

    client = SpendGuardClient(
        "ak_sandbox_" + "1" * 32,
        http=httpx.Client(base_url="http://mock.test", transport=httpx.MockTransport(hang)),
        sleep=lambda _: None,
    )
    gate = PaymentGate(
        client, world.provider, world.verifier, world.ledger, allowed_recipients=[VENDOR]
    )
    result = gate.pay(world.order("o-1"))
    assert result.status is PaymentStatus.NO_VERDICT and "timed out" in result.detail
    assert world.provider.payments() == []


def test_api_error_fails_closed(world: World) -> None:
    """R-160: an error response (here 401) is no verdict, so no payment"""
    # A placeholder key the mock doesn't know.
    # pragma: allowlist nextline secret
    world.client._api_key = "ak_sandbox_" + "f" * 32
    result = world.gate.pay(world.order("o-1"))
    assert result.status is PaymentStatus.NO_VERDICT and "401" in result.detail
    assert world.provider.payments() == []


# One key, one decision, one payment per order


def test_retry_after_outage_creates_one_decision(world: World) -> None:
    """R-167: retries for an order reuse its Idempotency-Key, so it gets one decision"""
    world.set_faults(error_rate=1.0)
    assert world.gate.pay(world.order("o-1")).status is PaymentStatus.NO_VERDICT
    world.set_faults(error_rate=0.0, rate_limit_burst=1)
    assert world.gate.pay(world.order("o-1")).paid
    assert len(world.decisions_for("o-1")) == 1


def test_denied_order_replays_its_decision(world: World) -> None:
    """R-167: asking again for a denied order returns the same decision, even after the
    velocity backoff: only deny_velocity starts a new attempt"""
    first = world.gate.pay(world.order("o-1", "720.00"))
    world.mock.clock.advance(seconds=61)
    second = world.gate.pay(world.order("o-1", "720.00"))
    assert second.decision == first.decision and len(world.decisions_for("o-1")) == 1
    assert [row["attempt"] for row in world.ledger.attempts("o-1")] == [1, 1]


def use_velocity_budget(world: World) -> None:
    """Ten decisions for this agent in the current 60 seconds; the next one is deny_velocity."""
    for _ in range(10):
        world.mock.decide(world.agent_key)


def test_velocity_denial_starts_a_new_attempt_after_backoff(world: World) -> None:
    """R-180, R-167: after deny_velocity the order keeps its key (asking early replays the
    denial) until the backoff passes; then it makes a new decision under attempt 2"""
    use_velocity_budget(world)
    denied = world.gate.pay(world.order("o-1"))
    assert (denied.status, denied.verdict) == (PaymentStatus.DENIED, "deny_velocity")
    assert denied.retry_at == world.mock.clock.now() + timedelta(seconds=60)
    world.mock.clock.advance(seconds=30)
    early = world.gate.pay(world.order("o-1"))
    assert early.decision == denied.decision and early.retry_at == denied.retry_at
    world.mock.clock.advance(seconds=30)
    paid = world.gate.pay(world.order("o-1"))
    assert paid.paid and paid.decision != denied.decision
    records = world.decisions_for("o-1")
    assert [r["metadata"]["attempt"] for r in records] == ["1", "2"]
    assert [row["attempt"] for row in world.ledger.attempts("o-1")] == [1, 1, 2]
    assert len(world.provider.payments()) == 1


def test_outage_after_velocity_backoff_reuses_the_new_attempt(world: World) -> None:
    """R-180, R-150: a 5xx during attempt 2 is retried under attempt 2, so the order ends
    with one decision per attempt and one payment"""
    use_velocity_budget(world)
    world.gate.pay(world.order("o-1"))
    world.mock.clock.advance(seconds=61)
    world.set_faults(error_rate=1.0)
    assert world.gate.pay(world.order("o-1")).status is PaymentStatus.NO_VERDICT
    world.set_faults(error_rate=0.0)
    assert world.gate.pay(world.order("o-1")).paid
    assert [r["metadata"]["attempt"] for r in world.decisions_for("o-1")] == ["1", "2"]
    assert [row["attempt"] for row in world.ledger.attempts("o-1")] == [1, 2, 2]


def test_changed_order_under_same_id_fails_closed(world: World) -> None:
    """R-167, R-160: the same order id with a different amount is a 409, so no payment"""
    world.gate.pay(world.order("o-1", "720.00"))
    result = world.gate.pay(world.order("o-1", "120.00"))
    assert result.status is PaymentStatus.NO_VERDICT and "409" in result.detail
    assert world.provider.payments() == []


def test_paid_order_is_not_paid_again(world: World) -> None:
    """R-172: a paid order is not authorized or paid a second time"""
    assert world.gate.pay(world.order("o-1")).paid
    again = world.gate.pay(world.order("o-1"))
    assert again.status is PaymentStatus.ALREADY_PAID
    assert len(world.provider.payments()) == 1 and len(world.decisions_for("o-1")) == 1


def test_parallel_payments_for_one_order_pay_once(world: World) -> None:
    """R-172, R-181: 20 concurrent pay() calls for one order: exactly one paid, the other 19
    already_paid (never a replay error), repeated over several orders"""

    def slow_verifier(token: str, order: Order) -> None:
        world.verifier(token, order)
        time.sleep(0.02)  # widen the gap between recording the nonce and claiming the order

    gate = PaymentGate(
        world.client, world.provider, slow_verifier, world.ledger,
        allowed_recipients=[VENDOR], clock=world.mock.clock,
    )  # fmt: skip
    for n in range(5):
        order = world.order(f"o-{n}")
        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(lambda _, o=order: gate.pay(o), range(20)))
        statuses = [result.status for result in results]
        assert statuses.count(PaymentStatus.PAID) == 1
        assert statuses.count(PaymentStatus.ALREADY_PAID) == 19, [r.detail for r in results]
        assert len(world.decisions_for(order.order_id)) == 1
    assert len(world.provider.payments()) == 5


def test_replay_for_an_order_another_process_paid_is_already_paid(world: World) -> None:
    """R-181: a second gate (another process: its own locks, the same ledger and nonce store)
    that loses the race after its pre-check reports already_paid, not a replay"""

    def verifier_that_loses_the_race(token: str, order: Order) -> None:
        world.gate.pay(order)  # the other process verifies, claims and pays first
        world.verifier(token, order)  # so this one sees the nonce as used

    second = PaymentGate(
        world.client, world.provider, verifier_that_loses_the_race, world.ledger,
        allowed_recipients=[VENDOR], clock=world.mock.clock,
    )  # fmt: skip
    result = second.pay(world.order("o-1"))
    assert result.status is PaymentStatus.ALREADY_PAID and "replay" not in result.detail
    assert len(world.provider.payments()) == 1


def test_replay_on_an_unclaimed_order_is_still_blocked(world: World) -> None:
    """R-181, R-209: a replayed approval for an order nobody claimed is blocked, not paid"""
    paid = world.gate.pay(world.order("o-1"))
    [row] = world.ledger.attempts("o-1")
    second = PaymentGate(
        world.client, world.provider, world.verifier, Ledger(),
        allowed_recipients=[VENDOR], clock=world.mock.clock,
    )  # fmt: skip
    replayed = Decision.model_validate(
        {**world.mock.body(world.mock.get(f"/v1/decisions/{paid.decision}")),
         "verdict_token": row["verdict_token"]}
    )  # fmt: skip
    result = second._act(world.order("o-1"), replayed)
    assert result.status is PaymentStatus.BLOCKED and "replay" in result.detail
    assert len(world.provider.payments()) == 1


def test_provider_error_keeps_order_claimed(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    """R-177: if the provider call fails, the order is not retried automatically"""

    def broken(**_: Any) -> Any:
        raise ConnectionError("provider unreachable")

    monkeypatch.setattr(world.provider, "pay", broken)
    result = world.gate.pay(world.order("o-1"))
    assert result.status is PaymentStatus.PROVIDER_ERROR and "person" in result.detail
    assert world.gate.pay(world.order("o-1")).status is PaymentStatus.ALREADY_PAID


# Credentials, logs and the ledger


def test_credentials_never_exposed(
    make_world: Callable[..., World],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """R-171: provider credentials and the agent key appear in no result, repr, ledger row
    or log line"""
    # A test placeholder, not a real credential.
    # pragma: allowlist nextline secret
    secret = "provider_secret_" + "9" * 32
    monkeypatch.setenv("MOCK_PROVIDER_SECRET", secret)
    world = make_world()
    provider = MockProvider(clock=world.mock.clock)
    gate = PaymentGate(
        world.client, provider, world.verifier, Ledger(),
        allowed_recipients=[VENDOR], clock=world.mock.clock,
    )  # fmt: skip
    with caplog.at_level(logging.INFO):
        results = [gate.pay(world.order(f"o-{n}", amount)) for n, amount in enumerate(["1", "720"])]
    visible = [repr(provider), repr(gate), repr(world.client), caplog.text]
    visible += [result.model_dump_json() for result in results]
    visible += [str(row) for row in gate.ledger.attempts()]
    for text in visible:
        assert secret not in text and world.agent_key not in text
    assert provider.payments()  # the secret was really used to pay


def test_logs_carry_decision_and_request_ids(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    """R-168, R-169: each payment attempt logs one JSON line with its dec_ and req_ ids"""
    with caplog.at_level(logging.INFO, logger="spend_guard"):
        result = world.gate.pay(world.order("o-1"))
    lines = [r.getMessage() for r in caplog.records if '"payment_attempt"' in r.getMessage()]
    assert len(lines) == 1
    assert result.decision is not None and result.request_id is not None
    assert result.decision in lines[0] and result.request_id in lines[0]
    assert "verdict_token" not in caplog.text and "eyJ" not in caplog.text


def test_ledger_is_append_only(world: World) -> None:
    """R-170: the ledger refuses UPDATE and DELETE on every table"""
    world.gate.pay(world.order("o-1"))
    conn = world.ledger._conn
    for table in ("attempts", "claims"):
        assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] > 0
        for sql in (f"UPDATE {table} SET order_id = 'x'", f"DELETE FROM {table}"):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                conn.execute(sql)


def test_ask_records_the_verdict_and_pays_nothing(world: World) -> None:
    """R-182: ask() on an allow reports `authorized` without verifying or paying; the next
    pay() replays that decision (one decision in the log) and pays once"""
    asked = world.gate.ask(world.order("o-1"))
    assert asked.status is PaymentStatus.AUTHORIZED and not asked.paid
    assert world.verifier.calls == 0 and world.provider.payments() == []
    paid = world.gate.pay(world.order("o-1"))
    assert paid.paid and paid.decision == asked.decision
    assert len(world.decisions_for("o-1")) == 1
    assert world.gate.ask(world.order("o-1")).status is PaymentStatus.ALREADY_PAID


def test_ask_never_treats_a_non_allow_as_payable(world: World) -> None:
    """R-182: ask() reports a denial, a review, an unapproved payee and an outage as pay()
    does in enforce mode, and stays that strict in observe mode"""
    assert world.gate.ask(world.order("o-1", "720.00")).status is PaymentStatus.DENIED
    review = world.gate.ask(world.order("o-2", "340.00"))
    assert review.status is PaymentStatus.PENDING_REVIEW and review.review
    blocked = world.gate.ask(world.order("o-3", recipient="vendor:new"))
    assert blocked.status is PaymentStatus.BLOCKED
    world.mock.post("/v1/enforcement", {"mode": "observe"})
    observed = world.gate.ask(world.order("o-4", "720.00"))
    assert observed.status is PaymentStatus.DENIED and observed.mode == "observe"
    world.set_faults(error_rate=1.0)
    assert world.gate.ask(world.order("o-5")).status is PaymentStatus.NO_VERDICT
    assert world.provider.payments() == []


def test_parallel_observe_mode_payments_pay_once(world: World) -> None:
    """R-172: in observe mode a denied order is paid, and there is no verifier or per-order
    lock on that path: the ledger's atomic claim alone makes 20 concurrent calls pay once"""
    world.mock.post("/v1/enforcement", {"mode": "observe"})
    for n in range(5):
        order = world.order(f"o-{n}", "720.00")
        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(lambda _, o=order: world.gate.pay(o), range(20)))
        statuses = [result.status for result in results]
        assert statuses.count(PaymentStatus.PAID) == 1, statuses
        assert statuses.count(PaymentStatus.ALREADY_PAID) == 19
    assert len(world.provider.payments()) == 5


def test_unreachable_api_fails_closed(world: World) -> None:
    """R-160: a refused connection (the API host is down) is no verdict, so no payment;
    the attempt is still written to the ledger"""
    gate = PaymentGate(
        unreachable_client(world.agent_key),
        world.provider,
        world.verifier,
        world.ledger,
        allowed_recipients=[VENDOR],
    )
    for result in (gate.pay(world.order("o-1")), gate.ask(world.order("o-2"))):
        assert result.status is PaymentStatus.NO_VERDICT and result.error is None
        assert "could not be reached" in result.detail
    assert [row["status"] for row in world.ledger.attempts()] == ["no_verdict", "no_verdict"]
    assert world.provider.payments() == []


def test_outage_fails_closed_in_observe_mode(world: World) -> None:
    """R-175: observe mode relaxes the verdict, not failing closed: with no verdict there
    is no payment in observe mode either"""
    set_mode(world, "observe")
    world.set_faults(error_rate=1.0)
    result = world.gate.pay(world.order("o-1"))
    assert result.status is PaymentStatus.NO_VERDICT
    assert result.error is not None and result.error.startswith("server_error: ")
    assert world.provider.payments() == []


def test_verdict_token_not_in_repr(world: World) -> None:
    """R-171: a decision's repr and str leave the verdict token out, so printing or
    logging a decision can't leak it"""
    decision = world.client.authorize(
        amount=Decimal("120.00"),
        currency="USD",
        recipient=VENDOR,
        category="saas",
        idempotency_key="o-1:1",
    )
    assert decision.verdict_token.count(".") == 2
    for text in (repr(decision), str(decision)):
        assert decision.verdict_token not in text and decision.verdict_token[:20] not in text


def test_order_refuses_a_float_amount_and_an_unsafe_order_id(world: World) -> None:
    """R-183: an order's amount is a Decimal, a string or an int, never a float; its id is
    printable ASCII with no spaces, because it goes into the Idempotency-Key header"""
    assert world.order("o-1", "8589934592.000001").amount == Decimal("8589934592.000001")
    assert Order(**{**world.order("o-1").model_dump(), "amount": "0.10"}).amount == Decimal("0.10")
    for bad in ({"amount": 0.1}, {"order_id": "café-1"}, {"order_id": "two words"}):
        with pytest.raises(ValidationError):
            Order(**{**world.order("o-1").model_dump(), **bad})


def test_allow_issued_before_a_revocation_is_still_payable(world: World) -> None:
    """R-184: an allow issued before the mandate was revoked stays valid until it expires,
    so an order authorized just before a revocation can still be paid inside five minutes;
    a new order after the revocation is denied"""
    order = world.order("o-1")
    assert world.gate.ask(order).status is PaymentStatus.AUTHORIZED
    assert world.mock.post(f"/v1/mandates/{world.mandate['mandate']}/revoke").status_code == 200
    world.mock.clock.advance(seconds=30)
    assert world.gate.pay(order).paid
    assert world.gate.pay(world.order("o-2")).verdict == "deny_revoked"
    assert len(world.provider.payments()) == 1
