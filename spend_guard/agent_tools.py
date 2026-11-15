"""The two tools a model gets: `check_spend` and `make_payment`.

They are plain methods on `SpendTools`. The MCP server (`mcp_server/`) and the
OpenAI Agents integration (`integrations/openai_agents/`) both register these
same methods, and the tests and evals call them directly.

What the model can and can't see:
- It sees a verdict, the API's own `reason`, ids, and one line of guidance.
- It never sees the agent key, the provider's credentials, the verdict token or
  anything about how tokens are signed. None of those are in any return value.
- An error returns the API's error code and message, or a fixed sentence. Never
  a traceback, a URL or this integration's internal detail.

`SpendTools` refuses to start with anything but an agent key: an organization
key could approve its own reviews, so it must never sit next to a model.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from decimal import Decimal
from typing import Any

from pydantic import ValidationError

from spend_guard.client import SpendGuardClient
from spend_guard.errors import ApiError, SpendGuardError
from spend_guard.gate import PaymentGate
from spend_guard.models import Order, PaymentResult, PaymentStatus

DENY = (
    "Denied. A deny is final for this request: do not retry it, do not split the amount "
    "into smaller payments, and do not change the category. Tell the user what was denied "
    "and the reason."
)
REVIEW = (
    "A human must approve this spend. Tell the user it is waiting for approval. Do not "
    "retry, split the amount or change the category while it waits."
)
VELOCITY = (
    "Too many requests in the last minute. Wait at least 60 seconds before asking again. "
    "Do not split the amount or change the category."
)
NO_VERDICT = (
    "The authorization service gave no answer, so nothing was paid and nothing can be. "
    "Do not try to pay another way. Tell the user, and try again later."
)
NOT_A_PAYEE = (
    "This recipient is not an approved payee, so a payment to it is blocked. Do not try "
    "another spelling of the recipient. Tell the user."
)
CHECK_ALLOW = (
    "Allowed right now. Nothing has been paid: this was only a check. To pay, call "
    "make_payment, which asks again and pays only if the answer is still allow."
)
API_ERROR = (
    "The authorization service answered with an error, so nothing was paid and nothing can "
    "be. Do not try to pay another way. Tell the user the error."
)
NO_ANSWER = "the authorization API did not answer"
INVALID = "The request was not valid, so nothing was sent. Fix the fields named and try again."

PAYMENT_GUIDANCE = {
    PaymentStatus.PAID: "Paid. Do not pay this order again.",
    PaymentStatus.AUTHORIZED: "Authorized, not paid yet. Nothing has been paid.",
    PaymentStatus.ALREADY_PAID: "This order was already paid. Nothing more was paid.",
    PaymentStatus.PENDING_REVIEW: REVIEW,
    PaymentStatus.DENIED: DENY,
    PaymentStatus.NO_VERDICT: NO_VERDICT,
    PaymentStatus.BLOCKED: (
        "Blocked by the payment gate's own checks, so nothing was paid. Do not retry. "
        "Tell the user."
    ),
    PaymentStatus.PROVIDER_ERROR: (
        "The payment provider failed and the outcome is unknown. Do not pay this order "
        "again. Tell the user a person must check."
    ),
}


def verdict_guidance(verdict: str) -> str:
    """One line for the model. Anything that isn't `allow` or `review` reads as a denial,
    including a code this server has never seen."""
    if verdict == "allow":
        return CHECK_ALLOW
    if verdict == "review":
        return REVIEW
    if verdict == "deny_velocity":
        return VELOCITY
    return DENY


def describe_invalid(error: ValidationError) -> str:
    fields = sorted({".".join(str(part) for part in item["loc"]) for item in error.errors()})
    return "invalid field(s): " + ", ".join(fields)


class SpendTools:
    def __init__(
        self,
        client: SpendGuardClient,
        gate: PaymentGate,
        *,
        new_check_id: Callable[[], str] = lambda: uuid.uuid4().hex,
    ) -> None:
        if client.key_class != "agent":
            raise ValueError(
                "the spend tools take an agent key (ak_...) only; "
                f"this client holds an {client.key_class} key"
            )
        self._client = client
        self._gate = gate
        self._new_check_id = new_check_id

    @property
    def gate(self) -> PaymentGate:
        return self._gate

    def check_spend(
        self,
        amount: Decimal | str,
        currency: str,
        recipient: str,
        category: str,
        purpose: str = "",
    ) -> dict[str, Any]:
        """Ask whether a spend would be authorized. Pays nothing."""
        check_id = f"check-{self._new_check_id()}"
        try:
            order = Order(
                order_id=check_id, amount=amount, currency=currency,
                recipient=recipient, category=category, purpose=purpose,
            )  # fmt: skip
        except ValidationError as error:
            return {"verdict": None, "error": describe_invalid(error), "guidance": INVALID}
        metadata = {"tool": "check_spend"}
        if order.purpose:
            metadata["purpose"] = order.purpose
        try:
            decision = self._client.authorize(
                amount=order.amount,
                currency=order.currency,
                recipient=order.recipient,
                category=order.category,
                idempotency_key=check_id,
                metadata=metadata,
            )
        except SpendGuardError as error:
            return {
                "verdict": None,
                "error": api_reason(error),
                "request_id": error.request_id,
                "guidance": API_ERROR if isinstance(error, ApiError) else NO_VERDICT,
            }
        guidance = verdict_guidance(decision.verdict)
        if order.recipient not in self._gate.allowed_recipients:
            guidance = NOT_A_PAYEE
        return {
            "verdict": decision.verdict,
            "reason": decision.reason,  # exactly as the API gave it
            "decision": decision.decision,
            "expires_at": decision.expires_at.isoformat() if decision.expires_at else None,
            "guidance": guidance,
        }

    def make_payment(
        self,
        order_id: str,
        amount: Decimal | str,
        currency: str,
        recipient: str,
        category: str,
        purpose: str = "",
    ) -> dict[str, Any]:
        """Pay through the gate: authorize again, verify the signed verdict, pay on allow."""
        try:
            order = Order(
                order_id=order_id, amount=amount, currency=currency,
                recipient=recipient, category=category, purpose=purpose,
            )  # fmt: skip
        except ValidationError as error:
            return {
                "status": "invalid_request",
                "paid": False,
                "error": describe_invalid(error),
                "guidance": INVALID,
            }
        result = self._gate.pay(order)
        view = payment_view(result)
        blocked = result.status is PaymentStatus.BLOCKED
        if blocked and order.recipient not in self._gate.allowed_recipients:
            view["guidance"] = NOT_A_PAYEE
        return view


def api_reason(error: SpendGuardError) -> str:
    """What to tell a model about a failed call: the API's own code and message when it
    answered, a fixed sentence when it didn't. Nothing else from the exception."""
    if isinstance(error, ApiError):
        return f"{error.code}: {error.api_message}"
    return NO_ANSWER


def payment_view(result: PaymentResult) -> dict[str, Any]:
    """The part of a `PaymentResult` a model may see. `detail` is left out: it is this
    integration's own explanation and can name internal checks."""
    guidance = PAYMENT_GUIDANCE[result.status]
    if result.status is PaymentStatus.DENIED and result.verdict == "deny_velocity":
        guidance = VELOCITY
    view: dict[str, Any] = {
        "status": result.status.value,
        "paid": result.paid,
        "order_id": result.order_id,
        "verdict": result.verdict,
        "reason": result.reason,  # exactly as the API gave it
        "decision": result.decision,
        "request_id": result.request_id,
        "guidance": guidance,
    }
    if result.status is PaymentStatus.NO_VERDICT:
        # The API's own code and message when it answered, a fixed sentence when it didn't.
        view["error"] = result.error or NO_ANSWER
        if result.error:
            view["guidance"] = API_ERROR
    if result.payment:
        view["payment"] = result.payment
    if result.review:
        view["review"] = result.review
        view["review_expires_at"] = (
            result.review_expires_at.isoformat() if result.review_expires_at else None
        )
    if result.retry_at:
        view["retry_at"] = result.retry_at.isoformat()
    return view
