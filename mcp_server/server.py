"""The MCP server: registers `check_spend` and `make_payment` with the official MCP SDK.

    python -m mcp_server          (stdio, for Claude Desktop or Claude Code)

The docstrings below are what the model reads, so they are short and factual.

Configuration comes from the environment, or from the file named by
SPEND_GUARD_ENV_FILE (see `.env.example` and docs/MCP.md).
The server holds an agent key, the payment gate and the provider. The model on
the other side of MCP gets only what the two tools return.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer

from spend_guard.agent_tools import SpendTools
from spend_guard.client import DEFAULT_BASE_URL, SpendGuardClient
from spend_guard.gate import PaymentGate
from spend_guard.jwks import KeySet
from spend_guard.ledger import Ledger
from spend_guard.nonces import SqliteNonceStore
from spend_guard.provider import MockProvider
from spend_guard.verify import VerdictVerifier

INSTRUCTIONS = (
    "Tools for spending money under a mandate. Every payment goes through make_payment, "
    "which checks the spend with an authorization service and pays only if the answer is "
    "allow. A deny is final for that request. You cannot pay any other way."
)


def build_server(tools: SpendTools) -> MCPServer:
    server = MCPServer("agent-spend-guard", instructions=INSTRUCTIONS)

    @server.tool()
    def check_spend(
        amount: str, currency: str, recipient: str, category: str, purpose: str = ""
    ) -> dict[str, Any]:
        """Ask whether a spend would be authorized. This pays nothing.

        Use it before proposing a purchase to the user. Each call is recorded and counts
        toward a limit of 10 per minute, so do not call it in a loop.

        Args:
            amount: The amount in major units, as a string such as "120.00".
            currency: The currency code, exactly as the mandate has it, e.g. "USD".
            recipient: Who would be paid, e.g. "vendor:acme_saas".
            category: The spend category, e.g. "saas".
            purpose: One line on what this is for.

        Returns the verdict (allow, review, or a deny_ code), the reason, the decision id,
        expires_at for an allow, and guidance. Follow the guidance. A deny is final for
        this request: do not retry, split the amount or change the category. For review,
        tell the user a human must approve.
        """
        return tools.check_spend(amount, currency, recipient, category, purpose)

    @server.tool()
    def make_payment(
        order_id: str,
        amount: str,
        currency: str,
        recipient: str,
        category: str,
        purpose: str = "",
    ) -> dict[str, Any]:
        """Pay for one order. This is the only way to pay.

        It always asks for authorization again, even after check_spend, and pays only if
        the answer is allow. Calling it twice with the same order_id never pays twice.

        Args:
            order_id: Your id for this purchase. Use one id per purchase and keep it the
                same if you call again for the same purchase.
            amount: The amount in major units, as a string such as "120.00".
            currency: The currency code, exactly as the mandate has it, e.g. "USD".
            recipient: Who is paid, e.g. "vendor:acme_saas".
            category: The spend category, e.g. "saas".
            purpose: One line on what this is for.

        Returns status (paid, already_paid, denied, pending_review, blocked, no_verdict,
        provider_error), whether it paid, the verdict and reason, and guidance. Follow the
        guidance. If status is denied, stop: do not retry, split the amount or change the
        category. If status is pending_review, tell the user a human must approve.
        """
        return tools.make_payment(order_id, amount, currency, recipient, category, purpose)

    return server


def split_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def tools_from_env(env: Mapping[str, str] = os.environ) -> SpendTools:
    """Build the client, verifier, provider and gate from environment variables."""
    key = env.get("SPEND_GUARD_AGENT_KEY", "")
    if not key.startswith("ak_"):
        # Say which class of key was given, never the key.
        given = "an organization key" if key.startswith("sk_") else "no agent key"
        raise SystemExit(
            f"SPEND_GUARD_AGENT_KEY must be an agent key (ak_...); got {given}. "
            "An organization key must never be given to an agent."
        )
    base_url = env.get("SPEND_GUARD_BASE_URL", DEFAULT_BASE_URL)
    client = SpendGuardClient(key, base_url)
    verifier = VerdictVerifier(
        jwks=KeySet(f"{base_url}/.well-known/jwks.json"),
        nonce_store=SqliteNonceStore(env.get("SPEND_GUARD_NONCE_DB", "nonces.db")),
        accepted_mandates=split_list(env.get("SPEND_GUARD_MANDATES", "")),
        allow_sandbox=True,  # the only API there is to point at is the local mock
    )
    gate = PaymentGate(
        client,
        MockProvider(env.get("SPEND_GUARD_PROVIDER_DB", "provider.db")),
        verifier,
        Ledger(env.get("SPEND_GUARD_LEDGER_DB", "ledger.db")),
        allowed_recipients=split_list(env.get("SPEND_GUARD_ALLOWED_RECIPIENTS", "")),
    )
    return SpendTools(client, gate)


def read_env_file(path: str) -> dict[str, str]:
    """Parse `NAME=value` lines. Used so an MCP client's config can point at a file
    instead of holding the agent key itself."""
    values: dict[str, str] = {}
    for line in Path(path).read_text().splitlines():
        name, separator, value = line.strip().partition("=")
        if separator and name and not name.startswith("#"):
            values[name.strip()] = value.strip()
    return values


def main() -> None:
    # stdout carries the MCP protocol, so logs go to stderr.
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    env = dict(os.environ)
    if env.get("SPEND_GUARD_ENV_FILE"):
        env = {**read_env_file(env["SPEND_GUARD_ENV_FILE"]), **env}
    build_server(tools_from_env(env)).run("stdio")


if __name__ == "__main__":
    main()
