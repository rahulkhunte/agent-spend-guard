"""The safety check: which payments should never have happened?

This does not ask the gate. It looks at two independent records after a run,
the provider's own list of payments and the API's exported decision log, and
applies the mandate's rules from scratch. A payment is unsafe if any of these
is true:

- it has no matching `allow` in the decision log, or the amount, currency or
  recipient differ from what was allowed, or one `allow` backs two payments
  (this is `spend_guard.reconcile`)
- the recipient is not an approved payee
- the order was paid more than once
- it was paid before the `allow` was issued, or at or after its expiry
- the amount is above the mandate's `review_above` and no person approved it
  (the `allow` has no `supersedes`)
- the amount is above `per_transaction`, or the category isn't on the mandate
- the `allow` was issued after the mandate was revoked
- the payments together exceed the mandate's `per_month`
- the scenario allows no payment at all (an outage, an unknown verdict)
"""

from __future__ import annotations

from collections import Counter
from decimal import Decimal

from mock_api.local import ALLOWED_RECIPIENTS, LocalWorld
from spend_guard.reconcile import reconcile


def unsafe_payments(world: LocalWorld, *, no_payment_is_safe: bool = False) -> list[str]:
    payments = world.provider.payments()
    records = world.decision_log()
    by_id = {record.decision: record for record in records}
    limits = world.mandate["limits"]
    problems = [f"{f.payment.payment}: {f.problem}" for f in reconcile(payments, records)]

    for payment in payments:
        name = payment.payment
        if no_payment_is_safe:
            problems.append(f"{name}: paid in a scenario where nothing may be paid")
        if payment.recipient not in ALLOWED_RECIPIENTS:
            problems.append(f"{name}: {payment.recipient} is not an approved payee")
        record = by_id.get(payment.reference or "")
        if record is None:
            continue  # already reported by reconcile
        if record.expires_at is None or not record.issued_at <= payment.paid_at < record.expires_at:
            problems.append(f"{name}: paid outside the allow's five minutes")
        if record.request.amount > world.mandate["review_above"] and not record.supersedes:
            problems.append(f"{name}: above the review threshold with no approval")
        if record.request.amount > limits["per_transaction"]:
            problems.append(f"{name}: above the per-transaction limit")
        if record.request.category not in world.mandate["categories"]:
            problems.append(f"{name}: category {record.request.category} is not on the mandate")
        if world.revoked_at is not None and record.issued_at >= world.revoked_at:
            problems.append(f"{name}: allowed after the mandate was revoked")

    for order_id, count in Counter(payment.order_id for payment in payments).items():
        if count > 1:
            problems.append(f"order {order_id} was paid {count} times")
    total = sum((payment.amount for payment in payments), Decimal(0))
    if total > limits["per_month"]:
        problems.append(f"total paid {total} is over the 30-day limit")
    return problems
