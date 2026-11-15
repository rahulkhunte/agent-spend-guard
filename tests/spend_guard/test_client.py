"""SpendGuardClient: retries, rate limits, request ids, and parsing decisions.

Transport edge cases (timeouts, a run of 5xx, a long Retry-After) use a fake
httpx transport; the rest run against the in-process mock.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import httpx
import pytest

from spend_guard.client import SpendGuardClient
from spend_guard.clock import FakeClock
from spend_guard.errors import ApiError, Unavailable
from spend_guard.jsonutil import decimal_text, dumps
from tests.spend_guard.conftest import VENDOR, World

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)

DECISION: dict[str, Any] = {
    "decision": "dec_0001",
    "request": {
        "agent": "agt_test",
        "amount": Decimal("120.00"),
        "currency": "USD",
        "recipient": VENDOR,
        "category": "saas",
    },
    "verdict": "allow",
    "reason": "within mandate mnd_0001",
    "mandate": "mnd_0001",
    "policy_version": "pol_2026-10-27.1",
    "nonce": "n_0001",
    "mode": "enforce",
    "issued_at": "2026-10-27T12:00:00Z",
    "expires_at": "2026-10-27T12:05:00Z",
    "verdict_token": "header.payload.signature",
}


def ok(body: dict[str, Any] = DECISION) -> httpx.Response:
    return httpx.Response(201, content=dumps(body).encode(), headers={"X-Request-Id": "req_ok"})


def error(status: int, code: str, request_id: str, **headers: str) -> httpx.Response:
    body = {"error": {"code": code, "message": "test", "request_id": request_id}}
    return httpx.Response(
        status, content=dumps(body).encode(), headers={"X-Request-Id": request_id, **headers}
    )


class Script:
    """A fake transport that plays back a list of responses (or exceptions) and records
    every request it saw."""

    def __init__(self, *steps: httpx.Response | Exception) -> None:
        self.steps = list(steps)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        step = self.steps.pop(0)
        if isinstance(step, Exception):
            raise step
        return step


def scripted(*steps: httpx.Response | Exception) -> tuple[SpendGuardClient, Script, list[float]]:
    script = Script(*steps)
    sleeps: list[float] = []
    http = httpx.Client(base_url="http://mock.test", transport=httpx.MockTransport(script))
    client = SpendGuardClient(
        "ak_sandbox_" + "1" * 32, http=http, clock=FakeClock(NOW), sleep=sleeps.append
    )
    return client, script, sleeps


def authorize(client: SpendGuardClient, amount: str = "120.00") -> Any:
    return client.authorize(
        amount=Decimal(amount),
        currency="USD",
        recipient=VENDOR,
        category="saas",
        idempotency_key="o-1:1",
    )


def test_denial_is_a_decision_not_an_error(world: World) -> None:
    """R-154: a deny_limit comes back as a Decision (201), not as an exception"""
    decision = authorize(world.client, "720.00")
    assert decision.verdict == "deny_limit"
    assert decision.reason == "amount 720.00 exceeds per_transaction limit 500.00"
    assert decision.request_id is not None and decision.request_id.startswith("req_")


def test_retry_after_5xx_reuses_idempotency_key() -> None:
    """R-150: a 5xx is retried with the same Idempotency-Key, with backoff"""
    client, script, sleeps = scripted(
        error(500, "server_error", "req_a"), error(503, "server_error", "req_b"), ok()
    )
    assert authorize(client).decision == "dec_0001"
    keys = [request.headers["Idempotency-Key"] for request in script.requests]
    assert keys == ["o-1:1"] * 3
    assert sleeps == [0.5, 1.0]


def test_retry_after_timeout_reuses_idempotency_key() -> None:
    """R-150: a timeout is retried with the same Idempotency-Key and the same body"""
    client, script, _ = scripted(httpx.ReadTimeout("slow"), httpx.ConnectTimeout("slow"), ok())
    assert authorize(client).verdict == "allow"
    assert {request.headers["Idempotency-Key"] for request in script.requests} == {"o-1:1"}
    assert len({request.content for request in script.requests}) == 1


def test_gives_up_after_max_attempts() -> None:
    """R-150, R-153: after the last retry, the last error is raised with its req_ id"""
    client, script, sleeps = scripted(*(error(500, "server_error", f"req_{n}") for n in range(3)))
    with pytest.raises(ApiError) as caught:
        authorize(client)
    assert caught.value.status == 500 and caught.value.request_id == "req_2"
    assert len(script.requests) == 3 and len(sleeps) == 2  # no sleep after the last attempt

    client, _, _ = scripted(*(httpx.ReadTimeout("slow") for _ in range(3)))
    with pytest.raises(Unavailable):
        authorize(client)


def test_4xx_is_not_retried() -> None:
    """R-153: a 400 is raised at once (a retry would only replay it), carrying its req_ id"""
    client, script, sleeps = scripted(error(400, "invalid_request", "req_bad"))
    with pytest.raises(ApiError) as caught:
        authorize(client)
    assert len(script.requests) == 1 and sleeps == []
    assert caught.value.code == "invalid_request"
    assert caught.value.request_id == "req_bad"
    assert "req_bad" in str(caught.value)


def test_error_carries_request_id(world: World) -> None:
    """R-153: an error from the API surfaces the X-Request-Id it was answered with"""
    client = SpendGuardClient("ak_sandbox_" + "f" * 32, http=world.mock.client)
    with pytest.raises(ApiError) as caught:
        authorize(client)
    assert caught.value.status == 401
    assert caught.value.request_id is not None and caught.value.request_id.startswith("req_")


def test_429_waits_retry_after(world: World) -> None:
    """R-151: on 429 the client waits Retry-After, then retries with the same key"""
    world.set_faults(rate_limit_burst=2, retry_after_seconds=3)
    decision = authorize(world.client)
    assert decision.verdict == "allow"
    assert world.sleeps == [3.0, 3.0]


def test_429_with_long_retry_after_raises() -> None:
    """R-151: a Retry-After longer than the client will wait is raised, not slept through"""
    client, script, sleeps = scripted(
        error(429, "rate_limited", "req_429", **{"Retry-After": "120"})
    )
    with pytest.raises(ApiError) as caught:
        authorize(client)
    assert caught.value.retry_after == 120 and sleeps == [] and len(script.requests) == 1


def test_reads_rate_limit_headers() -> None:
    """R-152: RateLimit-* headers are read; with nothing left, the next call waits for reset"""
    headers = {"RateLimit-Limit": "600", "RateLimit-Remaining": "0", "RateLimit-Reset": "20"}
    response = httpx.Response(201, content=dumps(DECISION).encode(), headers=headers)
    client, _, sleeps = scripted(response, ok())
    authorize(client)
    assert client.rate_limit is not None
    assert (client.rate_limit.limit, client.rate_limit.remaining) == (600, 0)
    authorize(client)
    assert sleeps == [20.0]


def test_rate_limit_wait_is_capped() -> None:
    """R-152: the wait for a reset never exceeds the caller's maximum wait (30 seconds by
    default); after that the call is sent"""
    headers = {"RateLimit-Limit": "600", "RateLimit-Remaining": "0", "RateLimit-Reset": "55"}
    response = httpx.Response(201, content=dumps(DECISION).encode(), headers=headers)
    client, script, sleeps = scripted(response, ok())
    authorize(client)
    authorize(client)
    assert sleeps == [30.0] and len(script.requests) == 2


def test_connection_failure_is_retried_then_unavailable() -> None:
    """R-150: a refused connection is "no answer", like a timeout: retried with the same
    Idempotency-Key, and raised as Unavailable (never as httpx's own error) when every
    attempt fails"""
    client, script, _ = scripted(httpx.ConnectError("refused"), ok())
    assert authorize(client).verdict == "allow"
    assert [request.headers["Idempotency-Key"] for request in script.requests] == ["o-1:1"] * 2

    client, script, _ = scripted(*(httpx.ConnectError("refused") for _ in range(3)))
    with pytest.raises(Unavailable, match="could not be reached"):
        authorize(client)
    assert len(script.requests) == 3


def test_unknown_response_fields_ignored() -> None:
    """R-156: a field the client doesn't know is ignored, not an error"""
    client, _, _ = scripted(ok({**DECISION, "risk_score": 3, "new_object": {"a": "b"}}))
    assert authorize(client).decision == "dec_0001"


@pytest.mark.parametrize("amount", ["8589934592.000001", "0.1", "340.50"])
def test_amount_sent_exactly(amount: str) -> None:
    """R-157: the amount goes over the wire as the exact decimal digits, never via a float"""
    client, script, _ = scripted(ok())
    authorize(client, amount)
    sent = decimal_text(Decimal(amount))  # 340.50 is written 340.5: same value, no float
    assert f'"amount":{sent}'.encode() in script.requests[0].content


def test_replay_is_flagged(world: World) -> None:
    """R-167: the same Idempotency-Key and body returns the original decision, marked replayed"""
    first = authorize(world.client)
    second = authorize(world.client)
    assert second.decision == first.decision and second.replayed and not first.replayed


def test_key_never_in_repr() -> None:
    """R-171: the client's repr never shows the API key"""
    client, _, _ = scripted()
    assert "ak_sandbox_" not in repr(client)
