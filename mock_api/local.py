"""A whole setup in one process: the mock API plus an integration wired to it.

The evals and `make demo` use this. Nothing listens on a port: the HTTP client talks
to the mock app in memory. Time is a `FakeClock`, so "wait 60 seconds" is instant.

`LocalWorld.build()` gives:
- the back office: an organization key and helpers that use it (create a mandate,
  approve a review, revoke, read the decision log)
- the agent side: a client holding only the agent key, a mock provider, a ledger,
  a nonce store, the real verifier, the payment gate and the model-facing tools
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

import httpx
from fastapi.testclient import TestClient

from mock_api.app import create_app
from mock_api.ids import new_key
from mock_api.settings import Settings
from spend_guard.agent_tools import SpendTools
from spend_guard.client import SpendGuardClient
from spend_guard.clock import FakeClock
from spend_guard.gate import PaymentGate
from spend_guard.jsonutil import dumps, loads
from spend_guard.jwks import KeySet
from spend_guard.ledger import Ledger
from spend_guard.models import Decision
from spend_guard.nonces import SqliteNonceStore
from spend_guard.provider import MockProvider
from spend_guard.verify import VerdictVerifier

START = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
ALLOWED_RECIPIENTS = ("vendor:acme_saas", "vendor:cloudly")
MANDATE: dict[str, Any] = {
    "principal": "role:procurement_lead",
    "limits": {
        "per_transaction": Decimal("500"),
        "per_month": Decimal("5000"),
        "currency": "USD",
    },
    "categories": ["saas"],
    "review_above": Decimal("250"),
    "expires": "2026-12-01",
}


class NoWebhooks:
    """Webhook deliveries go nowhere unless a caller passes its own sender."""

    def __call__(self, url: str, token: str) -> int:
        return 200


@dataclass
class LocalWorld:
    clock: FakeClock
    http: TestClient
    agent: str
    mandate: dict[str, Any]
    client: SpendGuardClient  # holds the agent key
    provider: MockProvider
    ledger: Ledger
    nonces: SqliteNonceStore
    verifier: VerdictVerifier
    gate: PaymentGate
    tools: SpendTools
    _org_key: str = field(repr=False, default="")
    revoked_at: datetime | None = None

    @classmethod
    def build(
        cls,
        *,
        sender: Any = None,
        agent_name: str = "procurement",
        allowed_recipients: tuple[str, ...] = ALLOWED_RECIPIENTS,
        start: datetime = START,
    ) -> LocalWorld:
        clock = FakeClock(start)
        org_key = new_key("sk")  # made fresh for this world; never printed
        settings = Settings(org_key=org_key, db_path=":memory:", webhook_interval=0, fault_seed=1)
        http = TestClient(create_app(settings, clock=clock, sender=sender or NoWebhooks()))
        world = cls.__new__(cls)
        world._org_key = org_key
        world.http = http
        world.clock = clock
        world.revoked_at = None
        created = world.org_post("/v1/agents", {"name": agent_name})
        world.agent = created["agent"]
        world.mandate = world.org_post("/v1/mandates", {**MANDATE, "agent": world.agent})
        world.client = SpendGuardClient(
            created["agent_key"], http=http, clock=clock, sleep=lambda _: None
        )
        world.provider = MockProvider(clock=clock)
        world.ledger = Ledger()
        world.nonces = SqliteNonceStore()
        world.verifier = VerdictVerifier(
            jwks=KeySet(f"{http.base_url}/.well-known/jwks.json", http=http),
            nonce_store=world.nonces,
            accepted_mandates=[world.mandate["mandate"]],
            allow_sandbox=True,  # the mock signs with a sandbox- key
            clock=clock,
        )
        world.gate = PaymentGate(
            world.client,
            world.provider,
            world.verifier,
            world.ledger,
            allowed_recipients=allowed_recipients,
            clock=clock,
        )
        world.tools = SpendTools(world.client, world.gate)
        return world

    # The back office. These use the organization key, which the agent side never gets.

    def org_post(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self._org_key}"}
        content = b""
        if body is not None:
            content = dumps(body).encode()
            headers["Content-Type"] = "application/json"
        response: httpx.Response = self.http.post(path, content=content, headers=headers)
        if response.status_code >= 400:
            raise RuntimeError(f"{path} answered {response.status_code}: {response.text[:200]}")
        result: dict[str, Any] = loads(response.content)
        return result

    def approve(self, review: str) -> str:
        """A person approves a review. Returns the `dec_` id of the new allow."""
        return str(self.org_post(f"/v1/reviews/{review}/approve")["decision"])

    def revoke_mandate(self) -> None:
        self.org_post(f"/v1/mandates/{self.mandate['mandate']}/revoke")
        self.revoked_at = self.clock.now()

    def set_mode(self, mode: str) -> None:
        self.org_post("/v1/enforcement", {"mode": mode})

    def set_faults(self, **faults: Any) -> None:
        # Fault rates are floats, which the Decimal-only `dumps` refuses, so plain json here.
        headers = {"Authorization": f"Bearer {self._org_key}", "Content-Type": "application/json"}
        response = self.http.post("/_mock/faults", content=json.dumps(faults), headers=headers)
        if response.status_code != 200:
            raise RuntimeError(f"faults answered {response.status_code}")

    def org_client(self) -> SpendGuardClient:
        """A client holding the organization key, for back-office code only."""
        return SpendGuardClient(
            self._org_key, http=self.http, clock=self.clock, sleep=lambda _: None
        )

    def decision_log(self) -> list[Decision]:
        """The API's exported decision log, read with the organization key."""
        today = self.clock.now().date()
        return self.org_client().export_records(date(2026, 1, 1), date(today.year + 1, 1, 1))

    def deliver_webhooks(self) -> None:
        """One delivery pass: the mock posts every due event to its subscribers."""
        self.http.app.state.mock.tick()  # type: ignore[attr-defined]
