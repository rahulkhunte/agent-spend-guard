"""The MCP tools, wired to the same in-process `world` the gate tests use."""

from __future__ import annotations

import json
from typing import Any

import pytest
from mcp.server.mcpserver import MCPServer

from mcp_server.server import build_server
from spend_guard.agent_tools import SpendTools
from tests.mock_api.conftest import make_mock  # noqa: F401  (fixture)
from tests.spend_guard.conftest import VENDOR, World, make_world, world  # noqa: F401  (fixtures)

SPEND = {"amount": "120.00", "currency": "USD", "recipient": VENDOR, "category": "saas"}


@pytest.fixture
def tools(world: World) -> SpendTools:  # noqa: F811
    return SpendTools(world.client, world.gate)


@pytest.fixture
def server(tools: SpendTools) -> MCPServer:
    return build_server(tools)


async def call(server: MCPServer, name: str, **arguments: Any) -> dict[str, Any]:
    """Call a tool the way an MCP client would, and parse the JSON text it returns."""
    result = await server.call_tool(name, arguments)
    assert not result.is_error, result.content
    return json.loads(result.content[0].text)
