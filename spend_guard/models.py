"""Typed shapes for what the client reads and what the gate takes and returns.

`verdict` and `mode` are plain strings, not enums: new decision
codes may be added later (SPEC section 6.4), and a client that refused to parse
them would lose the record. Code that acts on a verdict compares it with
`allow` and treats everything else, known or not, as a denial.

Unknown response fields are ignored, as SPEC section 19.1 asks.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

# The 8 decision codes. Anything else is unknown, and unknown is a denial.
KNOWN_VERDICTS = frozenset(
    {
        "allow",
        "review",
        "deny_limit",
        "deny_velocity",
        "deny_category",
        "deny_expired",
        "deny_revoked",
        "deny_no_mandate",
    }
)


class ApiModel(BaseModel):
    """Response models: ignore fields we don't know, never change what we parsed."""

    model_config = ConfigDict(extra="ignore", frozen=True)


class SpendRequest(ApiModel):
    """The request echo on a decision."""

    agent: str
    amount: Decimal
    currency: str
    recipient: str
    category: str


class Review(ApiModel):
    review: str
    waits_for: str
    expires_at: datetime
    status: str


class Decision(ApiModel):
    """A decision, whatever the verdict. A denial is a successful call, not an error."""

    decision: str
    request: SpendRequest
    verdict: str
    reason: str
    mandate: str | None = None  # absent on deny_no_mandate
    policy_version: str
    nonce: str
    mode: str
    issued_at: datetime
    expires_at: datetime | None = None  # allow only
    verdict_token: str = Field(repr=False)  # never in a repr or a log line
    supersedes: str | None = None  # review approvals only
    review: Review | None = None  # review only
    metadata: dict[str, str] | None = None

    # Set by the client from response headers; not part of the body.
    request_id: str | None = None
    replayed: bool = False


class Order(BaseModel):
    """One thing an agent wants to pay for. `order_id` is the integrator's own id."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # Printable ASCII with no spaces: the id goes into the Idempotency-Key header.
    order_id: str = Field(min_length=1, max_length=200, pattern=r"^[\x21-\x7e]+$")
    amount: Decimal = Field(gt=0)
    currency: str = Field(min_length=1, max_length=128)
    recipient: str = Field(min_length=1, max_length=1024)
    category: str = Field(min_length=1, max_length=128)
    purpose: str = Field(default="", max_length=500)

    @field_validator("amount", mode="before")
    @classmethod
    def no_float_amount(cls, value: object) -> object:
        """A binary float has already lost digits. Take a Decimal, a string or an int."""
        if isinstance(value, float):
            raise ValueError("amount must be a decimal string, not a float")
        return value


class PaymentStatus(StrEnum):
    PAID = "paid"  # money moved (in observe mode, possibly against a non-allow verdict)
    AUTHORIZED = "authorized"  # `ask` only: the verdict is allow; nothing verified or paid yet
    PENDING_REVIEW = "pending_review"  # a person must approve; nothing paid
    DENIED = "denied"  # the verdict was not allow and the decision said enforce
    BLOCKED = "blocked"  # stopped by this integration's own checks
    NO_VERDICT = "no_verdict"  # the API gave no verdict: failed closed
    ALREADY_PAID = "already_paid"  # this order was paid (or claimed) before
    PROVIDER_ERROR = "provider_error"  # the provider call failed; outcome needs a human


class PaymentResult(BaseModel):
    """What the gate tells its caller. Never contains credentials or the verdict token."""

    model_config = ConfigDict(frozen=True)

    status: PaymentStatus
    order_id: str
    decision: str | None = None  # dec_ id, the join key with the decision log
    verdict: str | None = None
    reason: str | None = None  # exactly the reason the API gave
    mode: str | None = None
    request_id: str | None = None  # req_ id, kept for when something went wrong
    review: str | None = None  # rev_ id when pending
    review_expires_at: datetime | None = None
    payment: str | None = None  # the provider's payment id
    retry_at: datetime | None = None  # deny_velocity: when this order may be tried again
    error: str | None = None  # no_verdict only: the API's own `code: message`, if it answered
    would_have_blocked: bool = False  # observe mode paid what enforce mode would have stopped
    detail: str = ""  # this integration's own explanation

    @property
    def paid(self) -> bool:
        return self.status is PaymentStatus.PAID
