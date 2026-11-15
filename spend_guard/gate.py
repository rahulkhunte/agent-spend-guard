"""PaymentGate: the only code that can reach the payment provider.

The authorization API blocks nothing by itself: it answers and records. The
stop has to live in the code that holds the payment credentials, not in the
agent's prompt. This class is that code. `pay(order)` runs these steps in order:

1. Already paid? An order is paid at most once.
2. Ask for a verdict, with the Idempotency-Key `<order_id>:<attempt>`. A
   timeout or a 5xx is retried under the same key, so it never makes a second
   decision. The attempt number goes up only after a `deny_velocity`, once the
   backoff has passed; every other verdict replays for 24 hours. No verdict
   (an error, a timeout, an outage): no payment. This is "fail closed".
3. Recipient allowlist. Mandates limit amounts and categories, not recipients,
   so this integration keeps its own list. Not on it: blocked, whatever the
   verdict, in either mode. Asking first means the attempt is in the decision
   log for audit, and the block is in the ledger with its `dec_` id.
4. Act on the verdict and the decision's own `mode`:
   - `allow`: verify the verdict token, then pay. A token that fails
     verification is never paid, in either mode.
   - anything else, in enforce mode: no payment. `review` returns
     `pending_review`; every other code, including one this code has never
     seen, is a denial.
   - anything else, in observe mode: pay, and record that enforce mode would
     have stopped it. That is what observe mode means.
   An unknown `mode` is treated as enforce.
5. Claim the order atomically in the ledger, then call the provider.

Every outcome is written to the append-only ledger with its `dec_` and `req_` ids.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Protocol

from spend_guard.client import SpendGuardClient
from spend_guard.clock import Clock, SystemClock
from spend_guard.errors import ApiError, ReplayError, SpendGuardError, VerificationError
from spend_guard.ledger import Ledger
from spend_guard.logs import log_event
from spend_guard.models import KNOWN_VERDICTS, Decision, Order, PaymentResult, PaymentStatus
from spend_guard.provider import PaymentProvider


class Verifier(Protocol):
    """Checks a verdict token against the order before money moves.
    Raises VerificationError (or a subclass) naming the check that failed."""

    def __call__(self, token: str, order: Order) -> None: ...


# Calls for the same order take the same lock while they verify and claim. A fixed
# number of locks, shared by order id hash, keeps memory bounded.
ORDER_LOCKS = 64

# The velocity rule counts an agent's decisions over 60 seconds, so after a deny_velocity
# the gate waits one full window before it lets the order make a new decision.
VELOCITY_BACKOFF = timedelta(seconds=60)


def idempotency_key(order: Order, attempt: int) -> str:
    """`<order_id>:<attempt>`. Retries within an attempt reuse it and get the same decision."""
    return f"{order.order_id}:{attempt}"


class PaymentGate:
    def __init__(
        self,
        client: SpendGuardClient,
        provider: PaymentProvider,
        verifier: Verifier,
        ledger: Ledger,
        *,
        allowed_recipients: Iterable[str],
        clock: Clock | None = None,
        velocity_backoff: timedelta = VELOCITY_BACKOFF,
    ) -> None:
        self._client = client  # holds an agent key, never an org key
        self._provider = provider  # holds the payment credentials
        self._verifier = verifier
        self.ledger = ledger
        self.allowed_recipients = frozenset(allowed_recipients)
        self.clock = clock or SystemClock()
        self.velocity_backoff = velocity_backoff
        self._order_locks = [threading.Lock() for _ in range(ORDER_LOCKS)]

    def __repr__(self) -> str:
        return f"PaymentGate(allowed_recipients={sorted(self.allowed_recipients)})"

    def pay(self, order: Order) -> PaymentResult:
        """Ask for a verdict for this order and pay only if the rules above allow it."""
        return self._run(order, settle=True)

    def ask(self, order: Order) -> PaymentResult:
        """Ask for this order's verdict and record it, without paying anything.

        It sends the same Idempotency-Key the next `pay(order)` will, so `pay` replays
        this decision instead of making a second one. An `allow` to an approved payee
        comes back as `authorized`: the token is not verified and the order is not
        claimed until `pay`. Anything else comes back exactly as `pay` reports it in
        enforce mode, whatever the decision's mode: `ask` never treats a non-allow as
        payable. A tool guardrail uses this to stop a payment tool before it runs."""
        return self._run(order, settle=False)

    def _run(self, order: Order, *, settle: bool) -> PaymentResult:
        if self.ledger.is_claimed(order.order_id):
            return self._finish(order, PaymentStatus.ALREADY_PAID, detail="order already paid")
        attempt = self._attempt(order)
        try:
            decision = self._client.authorize(
                amount=order.amount,
                currency=order.currency,
                recipient=order.recipient,
                category=order.category,
                idempotency_key=idempotency_key(order, attempt),
                metadata={"order_id": order.order_id, "attempt": str(attempt)},
            )
        except SpendGuardError as error:
            detail = f"no verdict, so no payment: {error}"
            return self._finish(
                order,
                PaymentStatus.NO_VERDICT,
                request_id=error.request_id,
                detail=detail,
                attempt=attempt,
                error=f"{error.code}: {error.api_message}" if isinstance(error, ApiError) else None,
            )
        return self._act(order, decision, attempt=attempt, settle=settle)

    def pay_approved(self, order: Order, approval: str) -> PaymentResult:
        """Pay an order whose review a person approved. `approval` is the `dec_` id of the
        new `allow` decision (from the approve call or the `decision.resolved` webhook).
        It must supersede the review decision this gate recorded for this order."""
        if self.ledger.is_claimed(order.order_id):
            return self._finish(order, PaymentStatus.ALREADY_PAID, detail="order already paid")
        review = self.ledger.pending_review(order.order_id)
        if review is None:
            detail = "no review was recorded for this order"
            return self._finish(order, PaymentStatus.BLOCKED, detail=detail)
        try:
            decision = self._client.get_decision(approval)
        except SpendGuardError as error:
            detail = f"could not read approval {approval}, so no payment: {error}"
            return self._finish(
                order, PaymentStatus.NO_VERDICT, request_id=error.request_id, detail=detail
            )
        if decision.supersedes != review:
            detail = f"decision {approval} does not supersede this order's review {review}"
            return self._finish(order, PaymentStatus.BLOCKED, decision=decision, detail=detail)
        return self._act(order, decision)

    # Steps

    def _attempt(self, order: Order) -> int:
        """The attempt number for this order's next authorization request.

        The same as last time, so a retry after a timeout or a 5xx reuses the key and
        can't make a second decision. One more only when the last attempt was stopped by
        `deny_velocity` and the backoff has passed since the gate first saw that denial."""
        last = self.ledger.last_attempt(order.order_id)
        if last is None:
            return 1
        velocity_denied = last.status == PaymentStatus.DENIED and last.verdict == "deny_velocity"
        if velocity_denied and last.decision and self.clock.now() >= self._retry_at(last.decision):
            return last.number + 1
        return last.number

    def _retry_at(self, decision: str) -> datetime:
        """When an order stopped by this deny_velocity decision may be tried again. Counted
        from the first time the gate saw the denial, so asking early doesn't push it back."""
        first_seen = self.ledger.first_seen(decision) or self.clock.now()
        return first_seen + self.velocity_backoff

    def _act(
        self,
        order: Order,
        decision: Decision,
        *,
        attempt: int | None = None,
        settle: bool = True,
    ) -> PaymentResult:
        """Decide what to do with a verdict. `attempt` is None for an approval read by id.
        `settle` is False for `ask`: stop before verifying and paying."""
        if order.recipient not in self.allowed_recipients:
            detail = f"recipient {order.recipient} is not on this integration's allowlist"
            return self._finish(
                order, PaymentStatus.BLOCKED, decision=decision, detail=detail, attempt=attempt
            )

        if decision.verdict == "allow" and not settle:
            return self._finish(order, PaymentStatus.AUTHORIZED, decision=decision, attempt=attempt)

        if decision.verdict == "allow":
            # Verify and claim as one step for this order. Concurrent calls for the order
            # share one decision and one nonce, so without the lock a loser could reach
            # the verifier just after the winner recorded the nonce, and see a "replay"
            # for an order that is simply being paid. With it, the loser finds the claim.
            with self._order_lock(order.order_id):
                if self.ledger.is_claimed(order.order_id):
                    return self._already_paid(order, decision, attempt)
                try:
                    self._verifier(decision.verdict_token, order)
                except VerificationError as error:
                    # A replay on an order that is now claimed: another process sharing
                    # the ledger and nonce store won the race. Report that, not a replay.
                    if isinstance(error, ReplayError) and self.ledger.is_claimed(order.order_id):
                        return self._already_paid(order, decision, attempt)
                    detail = f"verdict token failed verification: {error}"
                    return self._finish(
                        order, PaymentStatus.BLOCKED, decision=decision, detail=detail,
                        attempt=attempt,
                    )  # fmt: skip
                claimed = self.ledger.claim(order.order_id, decision.decision, self.clock.now())
            return self._pay(
                order, decision, claimed=claimed, would_have_blocked=False, attempt=attempt
            )

        if decision.mode != "observe" or not settle:  # enforce, an unknown mode, or `ask`
            if decision.verdict == "review":
                return self._finish(
                    order, PaymentStatus.PENDING_REVIEW, decision=decision, attempt=attempt
                )
            detail, retry_at = "", None
            if decision.verdict == "deny_velocity":
                retry_at = self._retry_at(decision.decision)
                detail = f"too many requests; this order may be tried again from {retry_at}"
            elif decision.verdict not in KNOWN_VERDICTS:
                detail = f"unrecognized verdict {decision.verdict}, treated as a denial"
            return self._finish(
                order,
                PaymentStatus.DENIED,
                decision=decision,
                detail=detail,
                retry_at=retry_at,
                attempt=attempt,
            )

        # Observe mode: let it through whatever the verdict, and say what enforce would do.
        claimed = self.ledger.claim(order.order_id, decision.decision, self.clock.now())
        return self._pay(order, decision, claimed=claimed, would_have_blocked=True, attempt=attempt)

    def _order_lock(self, order_id: str) -> threading.Lock:
        return self._order_locks[hash(order_id) % ORDER_LOCKS]

    def _already_paid(self, order: Order, decision: Decision, attempt: int | None) -> PaymentResult:
        return self._finish(
            order,
            PaymentStatus.ALREADY_PAID,
            decision=decision,
            detail="order already paid",
            attempt=attempt,
        )

    def _pay(
        self,
        order: Order,
        decision: Decision,
        *,
        claimed: bool,
        would_have_blocked: bool,
        attempt: int | None,
    ) -> PaymentResult:
        """Call the provider, but only for the caller whose claim on the order succeeded."""
        if not claimed:
            return self._already_paid(order, decision, attempt)
        try:
            payment = self._provider.pay(
                order_id=order.order_id,
                amount=order.amount,
                currency=order.currency,
                recipient=order.recipient,
                reference=decision.decision,
            )
        except Exception as error:  # any provider failure: we can't know if money moved
            detail = (
                f"provider call failed ({type(error).__name__}); the order stays claimed "
                "until a person checks the provider's records"
            )
            return self._finish(
                order, PaymentStatus.PROVIDER_ERROR, decision=decision, detail=detail,
                attempt=attempt,
            )  # fmt: skip
        detail = ""
        if would_have_blocked:
            detail = "observe mode: paid, but enforce mode would have blocked this"
        return self._finish(
            order,
            PaymentStatus.PAID,
            decision=decision,
            payment=payment.payment,
            would_have_blocked=would_have_blocked,
            detail=detail,
            attempt=attempt,
        )

    def _finish(
        self,
        order: Order,
        status: PaymentStatus,
        *,
        decision: Decision | None = None,
        request_id: str | None = None,
        payment: str | None = None,
        would_have_blocked: bool = False,
        detail: str = "",
        retry_at: datetime | None = None,
        attempt: int | None = None,
        error: str | None = None,
    ) -> PaymentResult:
        review = decision.review if decision is not None else None
        result = PaymentResult(
            status=status,
            order_id=order.order_id,
            decision=decision.decision if decision else None,
            verdict=decision.verdict if decision else None,
            reason=decision.reason if decision else None,  # exactly as the API gave it
            mode=decision.mode if decision else None,
            request_id=decision.request_id if decision else request_id,
            review=review.review if review else None,
            review_expires_at=review.expires_at if review else None,
            payment=payment,
            retry_at=retry_at,
            error=error,
            would_have_blocked=would_have_blocked,
            detail=detail,
        )
        token = decision.verdict_token if decision else None
        self.ledger.record(result, self.clock.now(), token, attempt)
        log_event(
            "payment_attempt",
            order=order.order_id,
            attempt=attempt,
            status=status.value,
            dec=result.decision,
            req=result.request_id,
            verdict=result.verdict,
            mode=result.mode,
            would_have_blocked=would_have_blocked or None,
        )
        return result
