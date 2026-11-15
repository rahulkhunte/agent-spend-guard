"""Request bodies the mock accepts, validated with pydantic.

Every model forbids unknown fields (SPEC section 4: a missing or unknown field
is 400). Amounts are Decimal and must arrive as JSON numbers.
"""

from __future__ import annotations

import re
from datetime import date
from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
)

from spend_guard.jsonutil import to_decimal

PositiveAmount = Annotated[Decimal, BeforeValidator(to_decimal), Field(gt=0)]
NonNegativeAmount = Annotated[Decimal, BeforeValidator(to_decimal), Field(ge=0)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=128)]
LongText = Annotated[str, StringConstraints(min_length=1, max_length=1024)]
Metadata = Annotated[
    dict[str, Annotated[str, StringConstraints(max_length=500)]], Field(max_length=20)
]
EventType = Literal[
    "decision.review_pending",
    "decision.resolved",
    "mandate.revoked",
    "mandate.expiring",
    "escrow.funded",
    "escrow.delivered",
    "escrow.released",
    "escrow.refunded",
    "escrow.disputed",
    "ping",
]


def iso_date(value: Any) -> date:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("must be a date string, YYYY-MM-DD")
    return date.fromisoformat(value)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AuthorizationRequest(StrictModel):
    amount: PositiveAmount
    currency: ShortText
    recipient: LongText
    category: ShortText
    protocol: Literal["x402", "mpp", "acp", "ap2", "card"] | None = None
    agent: str | None = None
    metadata: Metadata | None = None


class Limits(StrictModel):
    per_transaction: PositiveAmount
    per_month: PositiveAmount | None = None
    currency: ShortText


class EscrowTerms(StrictModel):
    required_above: str | None = None  # stored and returned, never enforced


class MandateCreate(StrictModel):
    principal: LongText
    agent: LongText
    limits: Limits
    categories: list[ShortText]
    review_above: NonNegativeAmount | None = None
    expires: Annotated[date, BeforeValidator(iso_date)]
    escrow: EscrowTerms | None = None


class AgentCreate(StrictModel):
    name: Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")]
    metadata: Metadata | None = None


class EnforcementSet(StrictModel):
    mode: Literal["observe", "enforce"]


class WebhookCreate(StrictModel):
    # The spec says HTTPS. The mock also allows local plain HTTP so the demo needs no TLS.
    url: Annotated[
        str, StringConstraints(pattern=r"^(https://|http://localhost[:/]|http://127\.0\.0\.1[:/])")
    ]
    events: Annotated[list[EventType], Field(min_length=1)]


class FaultsUpdate(StrictModel):
    latency_ms: int | None = None
    error_rate: float | None = None
    timeout_rate: float | None = None
    timeout_seconds: float | None = None
    rate_limit_burst: int | None = None
    retry_after_seconds: int | None = None
    forced_verdict: str | None = Field(default=None, max_length=128)


def describe(error: ValidationError) -> str:
    """One short, readable message for a 400."""
    first = error.errors()[0]
    where = ".".join(str(part) for part in first["loc"]) or "body"
    if first["type"] == "extra_forbidden":
        return f"unknown field: {where}"
    if first["type"] == "missing":
        return f"{where} is required"
    return f"{where}: {first['msg']}"
