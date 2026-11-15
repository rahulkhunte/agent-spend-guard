"""Test harness for the client and the gate, run against the mock in-process.

`world` is one agent with the standard test mandate, a client holding that agent's
key, a mock provider, an in-memory ledger, the real verifier and a gate
that allows `vendor:acme_saas`.
Sleeps are recorded, never slept.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

import httpx
import pytest

from spend_guard.client import SpendGuardClient
from spend_guard.gate import PaymentGate
from spend_guard.jwks import KeySet
from spend_guard.ledger import Ledger
from spend_guard.models import Order
from spend_guard.nonces import SqliteNonceStore
from spend_guard.provider import MockProvider
from spend_guard.verify import VerdictVerifier
from tests.mock_api.conftest import ORG_KEY, Mock, make_mock  # noqa: F401  (fixture)

VENDOR = "vendor:acme_saas"


def mock_keyset(mock: Mock, **settings: Any) -> KeySet:
    """The mock's public key set, fetched through the in-process test client."""
    return KeySet(f"{mock.client.base_url}/.well-known/jwks.json", http=mock.client, **settings)


def unreachable_client(key: str, **settings: Any) -> SpendGuardClient:
    """A client whose every call fails to connect, as when the API host is down."""

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    http = httpx.Client(base_url="http://down.test", transport=httpx.MockTransport(refuse))
    return SpendGuardClient(key, http=http, sleep=lambda _: None, **settings)


class CountingVerifier:
    """The real verifier, counting how often the gate calls it."""

    def __init__(self, inner: VerdictVerifier) -> None:
        self.inner = inner
        self.calls = 0

    def __call__(self, token: str, order: Order) -> None:
        self.calls += 1
        self.inner(token, order)


def real_verifier(mock: Mock, mandates: list[str]) -> CountingVerifier:
    """The mock is sandbox, so sandbox kids are allowed here."""
    verifier = VerdictVerifier(
        jwks=mock_keyset(mock),
        nonce_store=SqliteNonceStore(),
        accepted_mandates=mandates,
        allow_sandbox=True,
        clock=mock.clock,
    )
    return CountingVerifier(verifier)


@dataclass
class World:
    mock: Mock
    agent: str
    agent_key: str
    mandate: dict[str, Any]
    client: SpendGuardClient
    provider: MockProvider
    ledger: Ledger
    verifier: CountingVerifier
    gate: PaymentGate
    sleeps: list[float] = field(default_factory=list)

    def order(self, order_id: str, amount: str = "120.00", **fields: Any) -> Order:
        values: dict[str, Any] = {
            "order_id": order_id,
            "amount": Decimal(amount),
            "currency": "USD",
            "recipient": VENDOR,
            "category": "saas",
        }
        values.update(fields)
        return Order(**values)

    def decisions_for(self, order_id: str) -> list[dict[str, Any]]:
        """Every decision in the mock's log carrying this order id in its metadata."""
        return [
            record
            for record in self.mock.export()
            if (record.get("metadata") or {}).get("order_id") == order_id
        ]

    def set_faults(self, **faults: Any) -> None:
        # Fault rates are floats, which our Decimal-only dumps refuses, so plain json here.
        response = self.mock.post("/_mock/faults", raw=json.dumps(faults).encode())
        assert response.status_code == 200, response.text


@pytest.fixture
def make_world(make_mock: Callable[..., Mock]) -> Callable[..., World]:  # noqa: F811
    def build(*, mandate: dict[str, Any] | None = None, **mock_settings: Any) -> World:
        mock = make_mock(**mock_settings)
        agent, agent_key, created = mock.agent_with_mandate(**(mandate or {}))
        sleeps: list[float] = []
        client = SpendGuardClient(
            agent_key, http=mock.client, clock=mock.clock, sleep=sleeps.append
        )
        provider = MockProvider(clock=mock.clock)
        ledger = Ledger()
        verifier = real_verifier(mock, [created["mandate"]])
        gate = PaymentGate(
            client, provider, verifier, ledger, allowed_recipients=[VENDOR], clock=mock.clock
        )
        return World(
            mock, agent, agent_key, created, client, provider, ledger, verifier, gate, sleeps
        )

    return build


@pytest.fixture
def world(make_world: Callable[..., World]) -> World:
    return make_world()


__all__ = ["ORG_KEY", "VENDOR", "World"]
