"""A narrated end-to-end run, for a terminal or a screen share.

    make demo                          (or: uv run python -m demo)
    DEMO_PAUSE=0 uv run python -m demo   (no pauses)

Everything runs in this process: the mock authorization API, the payment gate, a
mock provider and a webhook receiver. Time is a fake clock. No network, no real
money, no API key.

The story: agent -> mandate -> allowed payment -> denied payment and a split
attempt -> review -> a person approves -> mandate revoked -> outage, fail
closed -> reconcile.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from decimal import Decimal
from typing import Any

from mock_api.local import LocalWorld
from spend_guard.models import Decision, Order
from spend_guard.reconcile import reconcile
from spend_guard.webhooks import WebhookReceiver

PAUSE = float(os.environ.get("DEMO_PAUSE", "1.2"))
VENDOR = "vendor:acme_saas"


def say(text: str = "") -> None:
    print(text, flush=True)


def step(number: int, title: str) -> None:
    time.sleep(PAUSE)
    say()
    say(f"── {number}. {title} " + "─" * max(0, 66 - len(title)))


def show(result: dict[str, Any]) -> None:
    line = f"   → status: {result['status']}"
    if result.get("verdict"):
        line += f"   verdict: {result['verdict']}"
    if result.get("payment"):
        line += f"   payment: {result['payment']}"
    say(line)
    if result.get("reason"):
        say(f"     reason from the API: {result['reason']}")
    say(f"     told to the agent:   {result['guidance']}")


def pay(world: LocalWorld, order_id: str, amount: str, **changes: str) -> dict[str, Any]:
    fields = {"currency": "USD", "recipient": VENDOR, "category": "saas", **changes}
    say(f"   agent calls make_payment({order_id}, {amount} {fields['currency']}, "
        f"{fields['recipient']}, {fields['category']})")  # fmt: skip
    result = world.tools.make_payment(order_id, Decimal(amount), **fields)
    show(result)
    world.clock.advance(seconds=2)
    return result


def main() -> int:
    logging.disable(logging.CRITICAL)  # the JSON logs would drown the story
    try:
        return story()
    finally:
        logging.disable(logging.NOTSET)


def story() -> int:
    humans: list[str] = []
    receivers: list[WebhookReceiver] = []

    def deliver(url: str, token: str) -> int:
        status, _ = receivers[0].handle(token.encode(), "application/jwt")
        return status

    world = LocalWorld.build(sender=deliver)

    def pay_the_approval(approval: Decision) -> None:
        """Runs in the back office when the approval webhook arrives."""
        request = approval.request
        order_id = (approval.metadata or {})["order_id"]
        order = Order(
            order_id=order_id, amount=request.amount, currency=request.currency,
            recipient=request.recipient, category=request.category,
        )  # fmt: skip
        result = world.gate.pay_approved(order, approval.decision)
        say(f"   webhook receiver → gate.pay_approved({order_id}) → status: "
            f"{result.status.value}   payment: {result.payment}")  # fmt: skip

    receivers.append(
        WebhookReceiver(
            jwks=world.verifier.jwks,
            client=world.org_client(),
            is_our_review=world.ledger.has_review,
            notify=humans.append,
            on_approval=pay_the_approval,
            allow_sandbox=True,
            clock=world.clock,
        )
    )
    world.org_post(
        "/v1/webhooks",
        {
            "url": "https://ops.example.com/hook",
            "events": ["decision.review_pending", "decision.resolved", "mandate.revoked"],
        },
    )

    say("agent-spend-guard demo")
    say("A limit in a prompt is a request. The check has to live in code that holds the")
    say("credentials. Everything below runs locally against a mock: no real money moves.")

    step(1, "An agent and its mandate")
    limits = world.mandate["limits"]
    say(f"   agent:   {world.agent}  (holds an agent key; cannot approve anything)")
    say(f"   mandate: {world.mandate['mandate']}")
    say(f"            up to {limits['per_transaction']} {limits['currency']} per payment, "
        f"{limits['per_month']} per 30 days,")  # fmt: skip
    say(f"            review above {world.mandate['review_above']}, "
        f"categories {world.mandate['categories']}")  # fmt: skip
    say(f"   approved payees (kept by the gate, not the mandate): "
        f"{sorted(world.gate.allowed_recipients)}")  # fmt: skip

    step(2, "A normal purchase is allowed and paid")
    paid = pay(world, "order-1", "120.00")
    say("   The gate asked the API, verified the signed verdict, then called the provider.")

    step(3, "An over-limit purchase is denied; splitting it in two pays nothing")
    pay(world, "order-2", "720.00")
    say("   The agent ignores the guidance and splits 720 into 2 × 360:")
    pay(world, "order-2a", "360.00")
    pay(world, "order-2b", "360.00")
    say("   Neither half is paid: each is above the review threshold and waits for a")
    say("   person. (Pieces under 250 would be paid; EVALS.md reports that limit.)")
    humans.clear()
    world.deliver_webhooks()
    humans.clear()  # the two halves' review notices aren't part of this story

    step(4, "A purchase above the review threshold waits for a person")
    review = pay(world, "order-3", "340.00")
    world.deliver_webhooks()
    say("   The API sent a signed decision.review_pending webhook. The receiver verified")
    say("   it, re-read the decision with its own key, and notified a person:")
    say(f"   *** HUMAN ACTION NEEDED *** {humans[-1]}")

    step(5, "The person approves; the approval is a new signed allow")
    approval = world.approve(review["review"])
    say(f"   back office approves {review['review']} with an organization key")
    say(f"   → new decision {approval}, superseding {review['decision']}")
    world.deliver_webhooks()
    again = world.gate.pay_approved(
        Order(order_id="order-3", amount=Decimal("340.00"), currency="USD",
              recipient=VENDOR, category="saas"),
        approval,
    )  # fmt: skip
    say(f"   using the same approval a second time → status: {again.status.value}")

    step(6, "The mandate is revoked; the next request is denied")
    world.revoke_mandate()
    say(f"   back office revokes {world.mandate['mandate']}")
    pay(world, "order-4", "60.00")

    step(7, "The authorization API goes down; the gate fails closed")
    world.set_faults(error_rate=1.0)
    pay(world, "order-5", "60.00")
    say("   No verdict, no payment. Breaking the check does not open the door.")
    world.set_faults(error_rate=0.0)

    step(8, "Reconcile: the provider's payments against the decision log")
    findings = reconcile(world.provider.payments(), world.decision_log())
    say(f"   {len(world.provider.payments())} provider payments, "
        f"{len(world.decision_log())} decisions, {len(findings)} unmatched")  # fmt: skip
    say("   Now someone pays the provider directly, skipping the gate:")
    world.provider.pay(
        order_id="off-the-books", amount=Decimal("999.00"), currency="USD",
        recipient="vendor:new", reference=None,
    )  # fmt: skip
    findings = reconcile(world.provider.payments(), world.decision_log())
    for finding in findings:
        say(f"   UNMATCHED {finding.payment.order_id} {finding.payment.amount} USD to "
            f"{finding.payment.recipient}: {finding.problem}")  # fmt: skip
    say("   A bypass can't be prevented from here, but without a matching allow it can't hide.")

    time.sleep(PAUSE)
    say()
    payments = [p for p in world.provider.payments() if p.reference]
    total = sum((p.amount for p in payments), Decimal(0))
    say(f"Done. Paid through the gate: {len(payments)} payments, {total:.2f} USD "
        f"({paid['order_id']} and order-3). Everything else was stopped.")  # fmt: skip
    ok = len(payments) == 2 and len(findings) == 1 and again.status.value == "already_paid"
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
