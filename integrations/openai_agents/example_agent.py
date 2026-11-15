"""A small "procurement assistant" on the OpenAI Agents SDK, paying through the gate.

    make mock                 (terminal 1)
    make seed                 (terminal 2, once per mock start)
    export OPENAI_API_KEY=...
    uv run python -m integrations.openai_agents.example_agent "Buy a 120 USD chat licence"

Without OPENAI_API_KEY it makes no model call and prints these steps instead. With
one, it calls the OpenAI API, which costs money. The payment side stays local: the
authorization API is the local mock, and the provider is the mock provider.
"""

from __future__ import annotations

import asyncio
import os
import sys

from agents import Agent

from integrations.openai_agents.tools import NeedsHuman, make_payment_tool, run_with_gate
from mcp_server.server import read_env_file, tools_from_env
from spend_guard.agent_tools import SpendTools

DEFAULT_MODEL = "gpt-4.1-mini"
DEFAULT_TASK = (
    "Buy a 120 USD team chat licence from vendor:acme_saas (category saas), then "
    "buy the 720 USD annual analytics plan from the same vendor."
)
INSTRUCTIONS = (
    "You are a procurement assistant. You buy software for the team with the make_payment "
    "tool, which is the only way to pay. Use one order_id per purchase. "
    "A deny is final for that request: do not retry it, do not split the amount into "
    "smaller payments, and do not change the category. Report what was paid and what was "
    "not, with the reason you were given."
)
HOW_TO_RUN = """OPENAI_API_KEY is not set, so no model was called.

To run the procurement assistant against the local mock:
  1. make mock          (terminal 1: the mock authorization API)
  2. make seed          (terminal 2: creates an agent and a mandate in .mock/agent.env)
  3. export OPENAI_API_KEY=...   (this step calls the OpenAI API and costs money)
  4. uv run python -m integrations.openai_agents.example_agent "Buy a 120 USD chat licence"

Optional: SPEND_GUARD_MODEL picks the model (default gpt-4.1-mini).
The tool and the guardrail are tested without a model in tests/integrations/."""


def build_agent(tools: SpendTools, *, model: str = DEFAULT_MODEL) -> Agent[None]:
    return Agent(
        name="procurement assistant",
        instructions=INSTRUCTIONS,
        model=model,
        tools=[make_payment_tool(tools)],
    )


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if not os.environ.get("OPENAI_API_KEY"):
        print(HOW_TO_RUN)
        return 0
    env = dict(os.environ)
    env_file = env.get("SPEND_GUARD_ENV_FILE", ".mock/agent.env")
    if os.path.isfile(env_file):
        env = {**read_env_file(env_file), **env}
    agent = build_agent(tools_from_env(env), model=env.get("SPEND_GUARD_MODEL", DEFAULT_MODEL))
    task = " ".join(arguments) or DEFAULT_TASK
    outcome = asyncio.run(run_with_gate(agent, task))
    if isinstance(outcome, NeedsHuman):
        print(f"NEEDS A HUMAN: {outcome.message}")
        print(f"  order {outcome.order_id}, review {outcome.review}")
        print(f"  expires {outcome.review_expires_at}; reason: {outcome.reason}")
    else:
        print(outcome)
    return 0


if __name__ == "__main__":
    sys.exit(main())
