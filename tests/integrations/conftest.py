"""The integration tests reuse the in-process `world` the gate tests use."""

from __future__ import annotations

import pytest

from spend_guard.agent_tools import SpendTools
from tests.mock_api.conftest import make_mock  # noqa: F401  (fixture)
from tests.spend_guard.conftest import World, make_world, world  # noqa: F401  (fixtures)


@pytest.fixture
def tools(world: World) -> SpendTools:  # noqa: F811
    return SpendTools(world.client, world.gate)
