"""The two MCP tools against the in-process mock: every verdict, a recipient off the
allowlist, an outage, an unknown verdict, 20 parallel calls, and what the model can see."""

from __future__ import annotations

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from mcp_server.server import build_server, read_env_file, tools_from_env
from spend_guard import agent_tools as tools_module
from spend_guard.agent_tools import SpendTools
from spend_guard.client import SpendGuardClient
from spend_guard.errors import ApiError, Unavailable
from spend_guard.gate import PaymentGate
from tests.mcp_server.conftest import SPEND, call
from tests.mock_api.conftest import ORG_KEY
from tests.spend_guard.conftest import VENDOR, World, unreachable_client

# Each deny code, with the request (or setup) that produces it against the test mandate.
DENIALS = ["deny_limit", "deny_category", "deny_expired", "deny_revoked", "deny_no_mandate"]


def arrange_denial(world: World, code: str) -> dict[str, str]:
    spend = dict(SPEND)
    if code == "deny_limit":
        spend["amount"] = "720.00"
    elif code == "deny_category":
        spend["category"] = "travel"
    elif code == "deny_expired":
        world.mock.clock.advance(days=60)
    elif code == "deny_revoked":
        world.mock.post(f"/v1/mandates/{world.mandate['mandate']}/revoke")
    elif code == "deny_no_mandate":
        spend["currency"] = "EUR"
    return spend


async def test_tools_are_listed_with_model_facing_docs(server: MCPServer) -> None:
    """R-243: both tools are registered, and their descriptions tell the model that a deny
    is final and that a review needs a human"""
    listed = {tool.name: tool for tool in await server.list_tools()}
    assert set(listed) == {"check_spend", "make_payment"}
    for tool in listed.values():
        description = " ".join(tool.description.split())
        assert "do not retry, split the amount or change the category" in description
        assert "a human must approve" in description
    assert listed["make_payment"].input_schema["required"] == [
        "order_id", "amount", "currency", "recipient", "category",
    ]  # fmt: skip


async def test_check_spend_allow_pays_nothing(server: MCPServer, world: World) -> None:
    """R-241: check_spend on an allow returns verdict, reason, decision id, expires_at and
    guidance, and pays nothing"""
    result = await call(server, "check_spend", **SPEND, purpose="team chat licences")
    assert result["verdict"] == "allow"
    assert result["reason"] == f"within mandate {world.mandate['mandate']}"
    assert result["decision"].startswith("dec_")
    assert result["expires_at"] == "2026-10-27T12:05:00+00:00"
    assert "Nothing has been paid" in result["guidance"]
    assert set(result) == {"verdict", "reason", "decision", "expires_at", "guidance"}
    assert world.provider.payments() == []


async def test_make_payment_allow_pays_once(server: MCPServer, world: World) -> None:
    """R-242: make_payment re-authorizes, verifies the token and pays on allow; a second
    call for the same order pays nothing more"""
    await call(server, "check_spend", **SPEND)
    paid = await call(server, "make_payment", order_id="o-1", **SPEND)
    assert paid["status"] == "paid" and paid["paid"] is True
    assert paid["payment"].startswith("pay_")
    assert world.verifier.calls == 1  # the gate verified the token before paying
    assert len(world.decisions_for("o-1")) == 1  # its own authorization, not the check's
    again = await call(server, "make_payment", order_id="o-1", **SPEND)
    assert again["status"] == "already_paid" and again["paid"] is False
    [payment] = world.provider.payments()
    assert payment.amount == Decimal("120.00") and payment.reference == paid["decision"]


@pytest.mark.parametrize("code", DENIALS)
async def test_each_denial_is_final_and_unpaid(server: MCPServer, world: World, code: str) -> None:
    """R-243: every deny code comes back from both tools with the API's reason unchanged
    and guidance that a deny is final; nothing is paid"""
    spend = arrange_denial(world, code)
    checked = await call(server, "check_spend", **spend)
    paid = await call(server, "make_payment", order_id="o-1", **spend)
    assert checked["verdict"] == paid["verdict"] == code
    assert checked["expires_at"] is None
    assert paid["status"] == "denied" and paid["paid"] is False
    [record] = world.decisions_for("o-1")
    assert paid["reason"] == record["reason"]
    for result in (checked, paid):
        assert "A deny is final" in result["guidance"]
        assert "do not split the amount" in result["guidance"]
    assert world.provider.payments() == []


async def test_deny_velocity_says_wait(server: MCPServer, world: World) -> None:
    """R-243: the 11th decision in a minute is deny_velocity; the tools say to wait, not to
    split or relabel, and make_payment gives retry_at"""
    for _ in range(10):
        world.mock.decide(world.agent_key)
    checked = await call(server, "check_spend", **SPEND)
    paid = await call(server, "make_payment", order_id="o-1", **SPEND)
    assert checked["verdict"] == paid["verdict"] == "deny_velocity"
    assert paid["status"] == "denied" and paid["retry_at"] == "2026-10-27T12:01:00+00:00"
    for result in (checked, paid):
        assert "Wait at least 60 seconds" in result["guidance"]
    assert world.provider.payments() == []


async def test_review_needs_a_human(server: MCPServer, world: World) -> None:
    """R-243: a review comes back as pending with its review id; the guidance says a human
    must approve, and nothing is paid"""
    spend = {**SPEND, "amount": "340.00"}
    checked = await call(server, "check_spend", **spend)
    paid = await call(server, "make_payment", order_id="o-1", **spend)
    assert checked["verdict"] == paid["verdict"] == "review"
    assert paid["status"] == "pending_review" and paid["paid"] is False
    assert paid["review"].startswith("rev_") and paid["review_expires_at"]
    for result in (checked, paid):
        assert "A human must approve" in result["guidance"]
    assert world.provider.payments() == []


async def test_recipient_off_the_allowlist_is_blocked(server: MCPServer, world: World) -> None:
    """R-242: a recipient that isn't an approved payee is blocked even though the API says
    allow, and both tools say so"""
    spend = {**SPEND, "recipient": "vendor:new"}
    checked = await call(server, "check_spend", **spend)
    paid = await call(server, "make_payment", order_id="o-1", **spend)
    assert checked["verdict"] == paid["verdict"] == "allow"
    assert paid["status"] == "blocked" and paid["paid"] is False
    for result in (checked, paid):
        assert "not an approved payee" in result["guidance"]
    assert world.provider.payments() == []


async def test_outage_fails_closed(server: MCPServer, world: World) -> None:
    """R-245: with the API answering 500, both tools report no verdict with the API's own
    error code and message, and nothing is paid"""
    world.set_faults(error_rate=1.0)
    checked = await call(server, "check_spend", **SPEND)
    paid = await call(server, "make_payment", order_id="o-1", **SPEND)
    assert checked["verdict"] is None
    assert checked["error"].startswith("server_error: ")
    assert checked["request_id"].startswith("req_")
    assert paid["status"] == "no_verdict" and paid["paid"] is False and paid["verdict"] is None
    assert paid["error"].startswith("server_error: ")
    for result in (checked, paid):
        assert result["guidance"] == tools_module.API_ERROR
        assert "nothing was paid" in result["guidance"]
    assert world.provider.payments() == []


def test_no_answer_is_a_fixed_sentence() -> None:
    """R-245: when the API never answered, the model gets a fixed sentence, not the
    exception's own text (which names the method and path)"""
    error = Unavailable("POST /v1/authorizations timed out after 3 attempt(s)")
    assert tools_module.api_reason(error) == "the authorization API did not answer"
    api = ApiError(400, "invalid_request", "unknown field: x", "req_1")
    assert tools_module.api_reason(api) == "invalid_request: unknown field: x"


async def test_unknown_verdict_reads_as_a_denial(make_world) -> None:  # type: ignore[no-untyped-def]
    """R-246: a decision code the tools have never seen gets denial guidance, and
    make_payment pays nothing"""
    world = make_world()
    world.set_faults(forced_verdict="deny_future_rule")
    server = build_server(SpendTools(world.client, world.gate))
    checked = await call(server, "check_spend", **SPEND)
    paid = await call(server, "make_payment", order_id="o-1", **SPEND)
    assert checked["verdict"] == paid["verdict"] == "deny_future_rule"
    assert paid["status"] == "denied" and paid["paid"] is False
    assert "A deny is final" in checked["guidance"] and "A deny is final" in paid["guidance"]
    assert world.provider.payments() == []


def test_twenty_parallel_calls_pay_once(tools: SpendTools, world: World) -> None:
    """R-247: 20 threads call make_payment for one order at once: exactly one pays, the
    other 19 report already_paid"""
    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(
            pool.map(
                lambda _: tools.make_payment("o-1", Decimal("120.00"), "USD", VENDOR, "saas"),
                range(20),
            )
        )
    statuses = [result["status"] for result in results]
    assert statuses.count("paid") == 1 and statuses.count("already_paid") == 19, statuses
    assert len(world.provider.payments()) == 1
    assert len(world.decisions_for("o-1")) == 1


async def test_twenty_parallel_calls_over_mcp_pay_once(server: MCPServer, world: World) -> None:
    """R-247: the same 20 calls sent through the MCP server at once pay exactly once"""
    results = await asyncio.gather(
        *(call(server, "make_payment", order_id="o-1", **SPEND) for _ in range(20))
    )
    assert sorted(r["status"] for r in results) == ["already_paid"] * 19 + ["paid"]
    assert len(world.provider.payments()) == 1


async def test_invalid_input_is_reported_without_internals(server: MCPServer, world: World) -> None:
    """R-245: a non-positive amount is refused before anything is sent, naming only the
    field"""
    spend = {**SPEND, "amount": "-5"}
    checked = await call(server, "check_spend", **spend)
    paid = await call(server, "make_payment", order_id="o-1", **spend)
    assert checked == {
        "verdict": None, "error": "invalid field(s): amount", "guidance": tools_module.INVALID,
    }  # fmt: skip
    assert paid["status"] == "invalid_request" and paid["error"] == "invalid field(s): amount"
    assert world.mock.export() == [] and world.provider.payments() == []


async def test_results_never_carry_secrets_or_tokens(server: MCPServer, world: World) -> None:
    """R-244: no tool result, on any path, contains the agent key, the verdict token, the
    provider's credential, or this integration's internal detail"""
    results = [
        await call(server, "check_spend", **SPEND),
        await call(server, "make_payment", order_id="o-1", **SPEND),
        await call(server, "make_payment", order_id="o-2", **{**SPEND, "amount": "720.00"}),
        await call(server, "make_payment", order_id="o-3", **{**SPEND, "amount": "340.00"}),
        await call(server, "make_payment", order_id="o-4", **{**SPEND, "recipient": "vendor:x"}),
    ]
    world.set_faults(error_rate=1.0)
    results.append(await call(server, "make_payment", order_id="o-5", **SPEND))
    text = json.dumps(results)
    tokens = [record["verdict_token"] for record in world.mock.export()]
    assert tokens and not any(token in text for token in tokens)
    assert world.agent_key not in text
    assert world.provider._MockProvider__secret not in text  # type: ignore[attr-defined]
    for word in ("verdict_token", "detail", "nonce", "eyJ", "Traceback", "allowlist", "http"):
        assert word not in text, word


def test_only_an_agent_key_is_accepted(world: World) -> None:
    """R-240: the tools refuse a client holding an organization key, and the server refuses
    to start from the environment with one; neither message shows the key"""
    org_client = SpendGuardClient(ORG_KEY, http=world.mock.client)
    with pytest.raises(ValueError, match="agent key") as refused:
        SpendTools(org_client, world.gate)
    assert ORG_KEY not in str(refused.value)
    for value in (ORG_KEY, ""):
        with pytest.raises(SystemExit) as stopped:
            tools_from_env({"SPEND_GUARD_AGENT_KEY": value})
        assert "must be an agent key" in str(stopped.value)
        assert ORG_KEY not in str(stopped.value)


def test_tools_from_env_builds_a_gate_with_an_agent_key(tmp_path, world: World) -> None:  # type: ignore[no-untyped-def]
    """R-240: with an agent key in the environment the server builds its own gate, with
    the allowlist and mandates it was given"""
    built = tools_from_env(
        {
            "SPEND_GUARD_AGENT_KEY": world.agent_key,
            "SPEND_GUARD_ALLOWED_RECIPIENTS": f"{VENDOR}, vendor:other",
            "SPEND_GUARD_MANDATES": world.mandate["mandate"],
            "SPEND_GUARD_NONCE_DB": str(tmp_path / "nonces.db"),
            "SPEND_GUARD_PROVIDER_DB": str(tmp_path / "provider.db"),
            "SPEND_GUARD_LEDGER_DB": str(tmp_path / "ledger.db"),
        }
    )
    assert built._gate.allowed_recipients == {VENDOR, "vendor:other"}
    assert built._client.key_class == "agent"


def test_env_file_is_parsed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """R-240: the server can read its settings from a file, so an MCP client's config
    doesn't have to hold the agent key"""
    path = tmp_path / "agent.env"
    path.write_text("# a comment\nSPEND_GUARD_MANDATES=mnd_1, mnd_2\n\nbroken line\nA = b\n")
    assert read_env_file(str(path)) == {"SPEND_GUARD_MANDATES": "mnd_1, mnd_2", "A": "b"}


async def test_make_payment_reports_the_api_error(server: MCPServer, world: World) -> None:
    """R-245: when the API refuses a payment request with an error, make_payment gives
    the model the API's own code and message, and does not say the API gave no answer"""
    first = await call(server, "make_payment", order_id="o-1", **{**SPEND, "amount": "720.00"})
    assert first["status"] == "denied"
    changed = await call(server, "make_payment", order_id="o-1", **{**SPEND, "amount": "20.00"})
    assert changed["status"] == "no_verdict" and changed["paid"] is False
    assert changed["error"].startswith("idempotency_conflict: ")
    assert changed["guidance"] == tools_module.API_ERROR
    assert world.provider.payments() == []


def test_unreachable_api_is_no_verdict_with_a_fixed_sentence(world: World) -> None:
    """R-245: with the API host down, both tools return a result (they do not raise): no
    verdict, the fixed sentence, and nothing paid"""
    client = unreachable_client(world.agent_key)
    gate = PaymentGate(
        client, world.provider, world.verifier, world.ledger, allowed_recipients=[VENDOR]
    )
    tools = SpendTools(client, gate)
    checked = tools.check_spend(**SPEND)
    paid = tools.make_payment(order_id="o-1", **SPEND)
    assert checked["verdict"] is None and paid["status"] == "no_verdict"
    for result in (checked, paid):
        assert result["error"] == "the authorization API did not answer"
        assert result["guidance"] == tools_module.NO_VERDICT
    assert world.provider.payments() == []


async def test_amount_must_be_a_string(server: MCPServer, world: World) -> None:
    """R-248: the tools' amount is a string in the schema, and a JSON number is refused
    before anything is sent, so an amount can't be rounded through a binary float"""
    for tool in await server.list_tools():
        assert tool.input_schema["properties"]["amount"] == {"title": "Amount", "type": "string"}
    for name, extra in (("check_spend", {}), ("make_payment", {"order_id": "o-1"})):
        with pytest.raises(ToolError):
            await server.call_tool(name, {**SPEND, **extra, "amount": 8589934592.000001})
    assert world.mock.export() == [] and world.provider.payments() == []
    exact = await call(server, "check_spend", **{**SPEND, "amount": "0.10"})
    assert exact["verdict"] == "allow"
    assert world.mock.export()[0]["request"]["amount"] == Decimal("0.10")


async def test_order_id_that_is_not_header_safe_is_invalid(server: MCPServer, world: World) -> None:
    """R-183: an order id with non-ASCII characters is reported as an invalid field, not
    a crash, and nothing is sent"""
    result = await call(server, "make_payment", order_id="café-1", **SPEND)
    assert result["status"] == "invalid_request" and result["error"] == "invalid field(s): order_id"
    assert world.mock.export() == []
