"""Test harness for the mock API: a fake clock, an in-memory database, a fake webhook sender."""

from __future__ import annotations

import itertools
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from jwt.api_jwk import PyJWK
from jwt.api_jws import PyJWS

from mock_api.app import MockState, create_app
from mock_api.settings import Settings
from spend_guard.clock import FakeClock
from spend_guard.jsonutil import dumps, loads

START = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
ORG_KEY = "sk_sandbox_" + "0" * 32  # a test placeholder, not a real key

_names = itertools.count(1)


class FakeSender:
    """Stands in for HTTP webhook delivery. Answers 200 unless told otherwise."""

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.calls: list[tuple[str, str, datetime]] = []
        self.statuses: list[int] = []
        self.default_status = 200

    def __call__(self, url: str, token: str) -> int:
        self.calls.append((url, token, self.clock.now()))
        return self.statuses.pop(0) if self.statuses else self.default_status


class Mock:
    def __init__(self, client: TestClient, clock: FakeClock, sender: FakeSender) -> None:
        self.client = client
        self.clock = clock
        self.sender = sender
        self.state: MockState = client.app.state.mock  # type: ignore[attr-defined]

    # HTTP helpers. Bodies are written with our Decimal-aware dumps.

    def post(
        self,
        path: str,
        body: Any = None,
        *,
        key: str | None = ORG_KEY,
        idem: str | None = None,
        raw: bytes | None = None,
    ) -> httpx.Response:
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        if idem is not None:
            headers["Idempotency-Key"] = idem
        content = raw if raw is not None else (dumps(body).encode() if body is not None else b"")
        if content:
            headers["Content-Type"] = "application/json"
        return self.client.post(path, content=content, headers=headers)

    def get(self, path: str, *, key: str | None = ORG_KEY, **params: str) -> httpx.Response:
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        return self.client.get(path, headers=headers, params=params)

    @staticmethod
    def body(response: httpx.Response) -> Any:
        """Parse a response keeping amounts as Decimal."""
        return loads(response.content)

    # Object helpers

    def new_agent(self, name: str | None = None) -> tuple[str, str]:
        response = self.post("/v1/agents", {"name": name or f"agent_{next(_names)}"})
        assert response.status_code == 201, response.text
        data = self.body(response)
        return data["agent"], data["agent_key"]

    def new_mandate(self, agent: str, **overrides: Any) -> dict[str, Any]:
        """The standard test mandate. Pass a field as None to leave it out."""
        body: dict[str, Any] = {
            "principal": "role:procurement_lead",
            "agent": agent,
            "limits": {
                "per_transaction": Decimal("500"),
                "per_month": Decimal("5000"),
                "currency": "USD",
            },
            "categories": ["saas"],
            "review_above": Decimal("250"),
            "expires": "2026-12-01",
        }
        body.update(overrides)
        body = {name: value for name, value in body.items() if value is not None}
        response = self.post("/v1/mandates", body)
        assert response.status_code == 201, response.text
        return self.body(response)

    def agent_with_mandate(self, **overrides: Any) -> tuple[str, str, dict[str, Any]]:
        agent, key = self.new_agent()
        return agent, key, self.new_mandate(agent, **overrides)

    def authorize(
        self, key: str, amount: str = "120.00", *, idem: str | None = None, **fields: Any
    ) -> httpx.Response:
        body = {
            "amount": Decimal(amount),
            "currency": "USD",
            "recipient": "vendor:acme_saas",
            "category": "saas",
            **fields,
        }
        return self.post("/v1/authorizations", body, key=key, idem=idem)

    def decide(self, key: str, amount: str = "120.00", **fields: Any) -> dict[str, Any]:
        response = self.authorize(key, amount, **fields)
        assert response.status_code == 201, response.text
        return self.body(response)

    def review(self, key: str, amount: str = "340.00", **fields: Any) -> dict[str, Any]:
        decision = self.decide(key, amount, **fields)
        assert decision["verdict"] == "review", decision
        return decision

    def export(self, start: str = "2026-10-01", end: str = "2027-01-01") -> list[dict[str, Any]]:
        response = self.get("/v1/exports/records", **{"from": start, "to": end})
        assert response.status_code == 200, response.text
        return [loads(line) for line in response.text.splitlines()]

    def claims(self, token: str) -> dict[str, Any]:
        """Check the signature against the mock's JWKS and return the claims, amounts as Decimal.
        Signature only: these tests inspect claims; verification is spend_guard.verify's job."""
        jwk = self.client.get("/.well-known/jwks.json").json()["keys"][0]
        payload = PyJWS().decode(token, PyJWK(jwk).key, algorithms=["ES256"])
        return loads(payload)

    def register_webhook(self, events: list[str], url: str = "https://ops.example.com/hook") -> str:
        response = self.post("/v1/webhooks", {"url": url, "events": events})
        assert response.status_code == 201, response.text
        return self.body(response)["webhook"]

    def delivered(self) -> list[dict[str, Any]]:
        """Run one delivery pass and return the claims of every event delivered so far."""
        self.state.tick()
        return [self.claims(token) for _, token, _ in self.sender.calls]


@pytest.fixture
def make_mock() -> Callable[..., Mock]:
    def build(**settings: Any) -> Mock:
        clock = FakeClock(START)
        sender = FakeSender(clock)
        config = Settings(
            org_key=ORG_KEY, db_path=":memory:", webhook_interval=0, fault_seed=1, **settings
        )
        app = create_app(config, clock=clock, sender=sender)
        return Mock(TestClient(app), clock, sender)

    return build


@pytest.fixture
def mock(make_mock: Callable[..., Mock]) -> Mock:
    return make_mock()
