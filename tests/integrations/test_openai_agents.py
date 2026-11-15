"""The OpenAI Agents SDK tool and guardrail, tested without a live model.

The tool and the guardrail are called directly. Three tests also run the SDK's own
agent loop, with `ScriptedModel` standing in for the LLM: it "decides" to call
make_payment with fixed arguments, so no network and no API key are involved.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from decimal import Decimal
from typing import Any

import pytest
from agents import Agent, FunctionTool, ModelResponse, RunConfig, Usage
from agents.models.interface import Model
from agents.tool_context import ToolContext
from agents.tool_guardrails import ToolInputGuardrailData
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from integrations.openai_agents import (
    NeedsHuman,
    make_payment_tool,
    payment_guardrail,
    run_with_gate,
)
from integrations.openai_agents.example_agent import build_agent, main
from integrations.openai_agents.tools import order_from_arguments
from spend_guard.agent_tools import SpendTools
from tests.spend_guard.conftest import VENDOR, World

SPEND = {"amount": "120.00", "currency": "USD", "recipient": VENDOR, "category": "saas"}
NO_TRACING = RunConfig(tracing_disabled=True)


class ScriptedModel(Model):
    """Stands in for the LLM: asks for each scripted tool call in turn, then says "done".
    It records what the tool told it, which is everything a real model would see."""

    def __init__(self, calls: list[dict[str, Any]]) -> None:
        self.calls = list(calls)
        self.seen: list[str] = []

    async def get_response(self, system_instructions: Any, input: Any, *_: Any, **__: Any) -> Any:
        if isinstance(input, list):
            self.seen = [
                str(item.get("output"))
                for item in input
                if isinstance(item, dict) and item.get("type") == "function_call_output"
            ]
        if self.calls:
            arguments = json.dumps(self.calls.pop(0))
            item: Any = ResponseFunctionToolCall(
                type="function_call", name="make_payment", arguments=arguments,
                call_id=f"call_{len(self.calls)}",
            )  # fmt: skip
        else:
            text = ResponseOutputText(type="output_text", text="done", annotations=[])
            item = ResponseOutputMessage(
                id="msg_1", type="message", role="assistant", status="completed", content=[text]
            )
        return ModelResponse(output=[item], usage=Usage(), response_id=None)

    def stream_response(self, *_: Any, **__: Any) -> AsyncIterator[Any]:
        raise NotImplementedError


def agent_with(tools: SpendTools, model: Model, *, guarded: bool = True) -> Agent[Any]:
    return Agent(
        name="procurement assistant",
        instructions="Buy what you are asked to buy.",
        model=model,
        tools=[make_payment_tool(tools, guarded=guarded)],
    )


async def invoke(tool: FunctionTool, **arguments: Any) -> dict[str, Any]:
    """Run the tool's own code, the way the SDK does once the guardrail has passed."""
    text = json.dumps(arguments)
    context = ToolContext(
        context=None, tool_name=tool.name, tool_call_id="call_1", tool_arguments=text
    )
    return json.loads(await tool.on_invoke_tool(context, text))


async def guard(tools: SpendTools, **arguments: Any) -> Any:
    """Run the guardrail alone on one tool call's arguments."""
    text = json.dumps(arguments)
    context = ToolContext(
        context=None, tool_name="make_payment", tool_call_id="call_1", tool_arguments=text
    )
    agent = Agent(name="test")
    return await payment_guardrail(tools).run(ToolInputGuardrailData(context=context, agent=agent))


async def test_tool_pays_through_the_gate(tools: SpendTools, world: World) -> None:
    """R-250: the make_payment function tool pays through the gate on allow, once per
    order, and the model-facing schema asks for the order fields"""
    tool = make_payment_tool(tools)
    assert tool.name == "make_payment"
    assert set(tool.params_json_schema["properties"]) == {
        "order_id", "amount", "currency", "recipient", "category", "purpose",
    }  # fmt: skip
    paid = await invoke(tool, order_id="o-1", **SPEND, purpose="chat licences")
    again = await invoke(tool, order_id="o-1", **SPEND, purpose="chat licences")
    assert paid["status"] == "paid" and again["status"] == "already_paid"
    assert world.verifier.calls == 1 and len(world.provider.payments()) == 1


async def test_tool_alone_never_pays_without_an_allow(tools: SpendTools, world: World) -> None:
    """R-250: even with the guardrail left off, the tool pays nothing on a denial, a
    review, an unapproved payee, a bad amount or an outage"""
    tool = make_payment_tool(tools, guarded=False)
    assert tool.tool_input_guardrails is None
    denied = await invoke(tool, order_id="o-1", **{**SPEND, "amount": "720.00"}, purpose="")
    review = await invoke(tool, order_id="o-2", **{**SPEND, "amount": "340.00"}, purpose="")
    blocked = await invoke(tool, order_id="o-3", **{**SPEND, "recipient": "vendor:new"}, purpose="")
    invalid = await invoke(tool, order_id="o-4", **{**SPEND, "amount": "lots"}, purpose="")
    world.set_faults(error_rate=1.0)
    outage = await invoke(tool, order_id="o-5", **SPEND, purpose="")
    statuses = [r["status"] for r in (denied, review, blocked, invalid, outage)]
    assert statuses == ["denied", "pending_review", "blocked", "invalid_request", "no_verdict"]
    assert world.provider.payments() == []


async def test_guardrail_lets_an_allow_through_without_a_second_decision(
    tools: SpendTools, world: World
) -> None:
    """R-251: on allow the guardrail lets the call run; the guardrail and the tool share
    one decision, and the guardrail itself pays nothing"""
    output = await guard(tools, order_id="o-1", **SPEND)
    assert output.behavior["type"] == "allow"
    assert output.output_info["status"] == "authorized" and output.output_info["paid"] is False
    assert world.provider.payments() == [] and world.verifier.calls == 0
    paid = await invoke(make_payment_tool(tools), order_id="o-1", **SPEND, purpose="")
    assert paid["status"] == "paid"
    assert len(world.decisions_for("o-1")) == 1


@pytest.mark.parametrize(
    ("change", "status", "phrase"),
    [
        ({"amount": "720.00"}, "denied", "A deny is final"),
        ({"category": "travel"}, "denied", "A deny is final"),
        ({"currency": "EUR"}, "denied", "A deny is final"),
        ({"recipient": "vendor:new"}, "blocked", "not an approved payee"),
        ({"amount": "-1"}, "invalid_request", "not valid"),
        ({"amount": "lots"}, "invalid_request", "not valid"),
    ],
)
async def test_guardrail_blocks_a_call_without_an_allow(
    tools: SpendTools, world: World, change: dict[str, str], status: str, phrase: str
) -> None:
    """R-251: without an allow the guardrail replaces the tool call with the refusal, so
    the tool's code never runs and nothing is paid"""
    output = await guard(tools, order_id="o-1", **{**SPEND, **change})
    assert output.behavior["type"] == "reject_content"
    refusal = json.loads(output.behavior["message"])
    assert refusal["status"] == status and refusal["paid"] is False
    assert phrase in refusal["guidance"]
    assert world.provider.payments() == []


async def test_guardrail_blocks_on_outage_and_unknown_verdict(make_world: Any) -> None:
    """R-251: no verdict, or a verdict the code has never seen, is not an allow: blocked"""
    for faults, status in (
        ({"error_rate": 1.0}, "no_verdict"),
        ({"forced_verdict": "deny_future_rule"}, "denied"),
    ):
        world = make_world()
        world.set_faults(**faults)
        output = await guard(SpendTools(world.client, world.gate), order_id="o-1", **SPEND)
        assert output.behavior["type"] == "reject_content"
        assert json.loads(output.behavior["message"])["status"] == status
        assert world.provider.payments() == []


async def test_guardrail_is_strict_in_observe_mode(tools: SpendTools, world: World) -> None:
    """R-251: in observe mode the gate would pay a denial; the guardrail still blocks the
    call, because it lets a tool run only on allow"""
    world.mock.post("/v1/enforcement", {"mode": "observe"})
    output = await guard(tools, order_id="o-1", **{**SPEND, "amount": "720.00"})
    assert output.behavior["type"] == "reject_content"
    assert world.provider.payments() == []


async def test_run_pays_on_allow(tools: SpendTools, world: World) -> None:
    """R-250, R-251: a full agent run (scripted model) that asks to pay an allowed order
    pays once and finishes normally"""
    model = ScriptedModel([{"order_id": "o-1", **SPEND, "purpose": "chat licences"}])
    outcome = await run_with_gate(agent_with(tools, model), "buy it", run_config=NO_TRACING)
    assert outcome == "done"
    assert json.loads(model.seen[0])["status"] == "paid"
    assert len(world.provider.payments()) == 1


async def test_run_continues_after_a_denial_without_paying(tools: SpendTools, world: World) -> None:
    """R-251: in a full run a denied call is replaced by the refusal; a model that then
    tries a smaller amount under another category is refused again, and nothing is paid"""
    model = ScriptedModel(
        [
            {"order_id": "o-1", **SPEND, "amount": "720.00", "purpose": ""},
            {"order_id": "o-1a", **SPEND, "amount": "200.00", "category": "travel", "purpose": ""},
        ]
    )
    outcome = await run_with_gate(agent_with(tools, model), "buy it", run_config=NO_TRACING)
    assert outcome == "done"
    assert [json.loads(seen)["status"] for seen in model.seen] == ["denied", "denied"]
    assert world.provider.payments() == []


async def test_review_stops_the_run_and_needs_a_human(tools: SpendTools, world: World) -> None:
    """R-252: a review stops the run with a NeedsHuman result carrying the review id; the
    model gets no further turn, nothing is paid, and after a person approves, the gate pays
    the approval for that order"""
    spend = {**SPEND, "amount": "340.00"}
    model = ScriptedModel(
        [
            {"order_id": "o-1", **spend, "purpose": "annual plan"},
            {"order_id": "o-2", **SPEND, "purpose": "should never be asked"},
        ]
    )
    outcome = await run_with_gate(agent_with(tools, model), "buy it", run_config=NO_TRACING)
    assert isinstance(outcome, NeedsHuman)
    assert outcome.order_id == "o-1" and outcome.review.startswith("rev_")
    assert "needs a human" in outcome.message and "nothing has been paid" in outcome.message
    assert len(model.calls) == 1  # the run stopped before the model's second call
    assert world.provider.payments() == []

    approved = world.mock.post(f"/v1/reviews/{outcome.review}/approve")
    assert approved.status_code == 201
    approval = world.mock.body(approved)["decision"]
    paid = world.gate.pay_approved(world.order("o-1", "340.00"), approval)
    assert paid.paid and len(world.provider.payments()) == 1


def test_example_prints_how_to_run_without_a_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """R-253: with no OPENAI_API_KEY the example makes no model call and prints how to
    run it"""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert main() == 0
    printed = capsys.readouterr().out
    assert "OPENAI_API_KEY is not set" in printed and "make seed" in printed


def test_example_agent_gets_only_the_guarded_payment_tool(tools: SpendTools) -> None:
    """R-253: the example's procurement assistant has exactly one tool, the guarded
    make_payment, and its instructions say a deny is final"""
    agent = build_agent(tools, model="any-model")
    [tool] = agent.tools
    assert tool.name == "make_payment" and len(tool.tool_input_guardrails) == 1
    assert "A deny is final" in agent.instructions


def test_guardrail_reads_a_json_number_amount_exactly() -> None:
    """R-251: if the model sends the amount as a JSON number, the guardrail reads it as an
    exact Decimal, never through a binary float"""
    arguments = (
        '{"order_id": "o-1", "amount": 8589934592.000001, "currency": "USD", '
        '"recipient": "vendor:acme_saas", "category": "saas"}'
    )
    assert order_from_arguments(arguments).amount == Decimal("8589934592.000001")
