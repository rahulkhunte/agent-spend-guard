"""The payment gate for the OpenAI Agents SDK (`openai-agents`).

Three pieces, each using a mechanism the SDK has today:

- `make_payment_tool(tools)`: a function tool backed by `PaymentGate`. It is the
  same `make_payment` the MCP server offers.
- `payment_guardrail(tools)`: a tool input guardrail. The SDK runs it before the
  tool's own code. It asks the gate for the order's verdict (`gate.ask`, which
  pays nothing) and lets the call through only when the verdict is `allow` to an
  approved payee. A denial replaces the tool call with the refusal. A `review`
  halts the run.
- `run_with_gate(agent, input)`: runs the agent and turns that halt into a
  `NeedsHuman` result, so "a person must approve" is the outcome of the run and
  not something the model has to remember to say.

Why a guardrail when the gate already refuses to pay: the gate is the control,
and the guardrail is a second line in front of it. Attach the same guardrail to
any other tool that can move money, and that tool can't run without an `allow`
either. `gate.ask` and `gate.pay` send the same Idempotency-Key for an order,
so the guardrail and the tool share one decision.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

from agents import (
    Agent,
    FunctionTool,
    RunConfig,
    Runner,
    ToolGuardrailFunctionOutput,
    ToolInputGuardrail,
    ToolInputGuardrailData,
    ToolInputGuardrailTripwireTriggered,
    function_tool,
)
from pydantic import ValidationError

from spend_guard.agent_tools import INVALID, NOT_A_PAYEE, SpendTools, describe_invalid, payment_view
from spend_guard.models import Order, PaymentStatus

NEEDS_HUMAN = (
    "This payment needs a human. It is waiting for approval and nothing has been paid. "
    "Ask the approver to approve or deny the review; the agent cannot approve it."
)


@dataclass(frozen=True)
class NeedsHuman:
    """What a run ends with when a payment went to review."""

    order_id: str
    review: str | None  # rev_ id, for the person who approves
    review_expires_at: str | None
    decision: str | None  # dec_ id of the review decision
    reason: str | None  # exactly as the API gave it
    message: str = NEEDS_HUMAN


def order_from_arguments(arguments: str | None) -> Order:
    """Build the order a payment tool call is about, from the JSON the model sent."""
    data = json.loads(arguments or "{}", parse_float=Decimal)  # no binary floats
    if not isinstance(data, dict):
        raise ValueError("tool arguments must be a JSON object")
    try:
        amount = Decimal(str(data.get("amount")))
    except InvalidOperation as error:
        raise ValueError("amount is not a number") from error
    return Order(
        order_id=data.get("order_id"),
        amount=amount,
        currency=data.get("currency"),
        recipient=data.get("recipient"),
        category=data.get("category"),
        purpose=data.get("purpose") or "",
    )


def payment_guardrail(tools: SpendTools) -> ToolInputGuardrail[Any]:
    """A tool input guardrail: no `allow`, no tool call."""

    def require_allow(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
        try:
            order = order_from_arguments(data.context.tool_arguments)
        except ValidationError as error:
            refusal = {"status": "invalid_request", "paid": False, "guidance": INVALID}
            refusal["error"] = describe_invalid(error)
            return ToolGuardrailFunctionOutput.reject_content(json.dumps(refusal), refusal)
        except ValueError as error:
            refusal = {"status": "invalid_request", "paid": False, "guidance": INVALID}
            refusal["error"] = str(error)
            return ToolGuardrailFunctionOutput.reject_content(json.dumps(refusal), refusal)

        result = tools.gate.ask(order)
        view = payment_view(result)
        if result.status is PaymentStatus.AUTHORIZED and result.verdict == "allow":
            return ToolGuardrailFunctionOutput.allow(view)
        if result.status is PaymentStatus.PENDING_REVIEW:
            needs_human = NeedsHuman(
                order_id=result.order_id,
                review=view.get("review"),
                review_expires_at=view.get("review_expires_at"),
                decision=result.decision,
                reason=result.reason,
            )
            return ToolGuardrailFunctionOutput.raise_exception(needs_human)
        if result.status is PaymentStatus.BLOCKED:
            if order.recipient not in tools.gate.allowed_recipients:
                view["guidance"] = NOT_A_PAYEE
        return ToolGuardrailFunctionOutput.reject_content(json.dumps(view), view)

    return ToolInputGuardrail(guardrail_function=require_allow, name="require_allow")


def make_payment_tool(tools: SpendTools, *, guarded: bool = True) -> FunctionTool:
    """The `make_payment` function tool. With `guarded` (the default) the guardrail
    above runs before every call."""

    def make_payment(
        order_id: str,
        amount: str,
        currency: str,
        recipient: str,
        category: str,
        purpose: str = "",
    ) -> str:
        """Pay for one order. This is the only way to pay.

        It always asks for authorization and pays only if the answer is allow. Calling
        it twice with the same order_id never pays twice. If the result's status is
        denied, stop: do not retry, split the amount or change the category. If it is
        pending_review, tell the user a human must approve.

        Args:
            order_id: Your id for this purchase. One id per purchase.
            amount: The amount in major units, as a string such as "120.00".
            currency: The currency code, exactly as the mandate has it, e.g. "USD".
            recipient: Who is paid, e.g. "vendor:acme_saas".
            category: The spend category, e.g. "saas".
            purpose: One line on what this is for.
        """
        try:
            value = Decimal(amount)
        except InvalidOperation:
            refusal = {"status": "invalid_request", "paid": False, "guidance": INVALID}
            return json.dumps({**refusal, "error": "invalid field(s): amount"})
        result = tools.make_payment(order_id, value, currency, recipient, category, purpose)
        return json.dumps(result)

    guardrails = [payment_guardrail(tools)] if guarded else None
    return function_tool(make_payment, tool_input_guardrails=guardrails)


async def run_with_gate(
    agent: Agent[Any], task: str, *, run_config: RunConfig | None = None, max_turns: int = 10
) -> str | NeedsHuman:
    """Run the agent. Returns its final answer, or `NeedsHuman` when a payment went to
    review: the run stops there, and a person takes over."""
    try:
        result = await Runner.run(agent, task, run_config=run_config, max_turns=max_turns)
    except ToolInputGuardrailTripwireTriggered as stopped:
        info = stopped.output.output_info
        if isinstance(info, NeedsHuman):
            return info
        raise
    return str(result.final_output)
