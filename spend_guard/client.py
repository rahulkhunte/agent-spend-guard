"""A small typed client for the authorization API (the local mock by default).

Retry rules (SPEC section 19.1):
- Retry only on a timeout or a 5xx, and always with the same `Idempotency-Key`.
  The API replays the original decision for a retry after a timeout, and stores
  nothing for a 5xx, so a retry can never create a second decision.
- On 429, wait `Retry-After` seconds, then retry. If the wait is longer than
  `max_wait_seconds`, give up and raise instead of blocking the caller.
- Every other error is raised at once: retrying a 400 just replays the 400.
- `RateLimit-*` headers are read on every response. When the last one said
  nothing is left, the next call waits for the window to reset.

A denial is a 201 and comes back as a `Decision`, never as an exception.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Any

import httpx
from pydantic import ValidationError

from spend_guard.clock import Clock, SystemClock
from spend_guard.errors import ApiError, SpendGuardError, Unavailable
from spend_guard.jsonutil import dumps, loads
from spend_guard.logs import log_event
from spend_guard.models import Decision

DEFAULT_BASE_URL = "http://127.0.0.1:8787"  # the local mock; there is no hosted API


@dataclass(frozen=True)
class RateLimitState:
    limit: int
    remaining: int
    reset_seconds: float
    seen_at: datetime


class SpendGuardClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        *,
        http: httpx.Client | None = None,
        timeout: float = 10.0,  # seconds, per attempt
        max_attempts: int = 3,
        backoff_seconds: float = 0.5,
        max_wait_seconds: float = 30.0,
        clock: Clock | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._api_key = api_key
        # An injected http client brings its own timeout settings.
        self._http = http or httpx.Client(base_url=base_url, timeout=timeout)
        self.max_attempts = max_attempts
        self.backoff_seconds = backoff_seconds
        self.max_wait_seconds = max_wait_seconds
        self.clock = clock or SystemClock()
        self.sleep = sleep
        self.rate_limit: RateLimitState | None = None  # from the last response that had headers

    def __repr__(self) -> str:  # never show the key
        return f"SpendGuardClient(base_url={str(self._http.base_url)!r})"

    @property
    def key_class(self) -> str:
        """`agent`, `organization` or `unknown`, from the key's prefix. Lets code that must
        only ever hold an agent key (the MCP server, an agent tool) check, without
        exposing the key itself."""
        if self._api_key.startswith("ak_"):
            return "agent"
        if self._api_key.startswith("sk_"):
            return "organization"
        return "unknown"

    # Endpoints

    def authorize(
        self,
        *,
        amount: Decimal,
        currency: str,
        recipient: str,
        category: str,
        idempotency_key: str,
        protocol: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> Decision:
        """POST /v1/authorizations. Returns the decision whatever the verdict.

        Raises ApiError or Unavailable when there is no verdict. The idempotency key is
        required, because it is what makes a retry safe."""
        body: dict[str, Any] = {
            "amount": amount,
            "currency": currency,
            "recipient": recipient,
            "category": category,
        }
        if protocol is not None:
            body["protocol"] = protocol
        if metadata:
            body["metadata"] = metadata
        response = self._send("POST", "/v1/authorizations", body=body, idem=idempotency_key)
        return self._decision(response)

    def get_decision(self, decision_id: str) -> Decision:
        """GET /v1/decisions/{id}. An agent key reads only its own decisions."""
        return self._decision(self._send("GET", f"/v1/decisions/{decision_id}"))

    def get_mandate(self, mandate_id: str) -> dict[str, Any]:
        """GET /v1/mandates/{id} (org key). Returned as parsed JSON: nothing here acts on
        a mandate's fields, so it has no model."""
        result: dict[str, Any] = loads(self._send("GET", f"/v1/mandates/{mandate_id}").content)
        return result

    def export_records(self, start: date, end: date) -> list[Decision]:
        """GET /v1/exports/records (org key): every decision from `start` (inclusive)
        to `end` (exclusive), parsed from NDJSON."""
        params = {"from": start.isoformat(), "to": end.isoformat()}
        response = self._send("GET", "/v1/exports/records", params=params)
        return [self._parse_decision(loads(line)) for line in response.text.splitlines()]

    # Transport

    def _send(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        idem: str | None = None,
        params: dict[str, str] | None = None,
    ) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self._api_key}"}
        content = None
        if body is not None:
            content = dumps(body).encode()  # Decimal amounts stay exact; floats are refused
            headers["Content-Type"] = "application/json"
        if idem is not None:
            headers["Idempotency-Key"] = idem
        # A POST without an Idempotency-Key is not safe to retry.
        attempts = self.max_attempts if method == "GET" or idem is not None else 1

        last: SpendGuardError = Unavailable(f"{method} {path}: no attempt made")
        for attempt in range(1, attempts + 1):
            self._wait_for_rate_limit()
            try:
                response = self._http.request(
                    method, path, content=content, headers=headers, params=params
                )
            except httpx.TransportError as error:
                # Timeouts, refused connections, DNS failures and resets: no answer at all.
                timed_out = isinstance(error, httpx.TimeoutException)
                event = "api_timeout" if timed_out else "api_unreachable"
                log_event(event, method=method, path=path, attempt=attempt)
                what = "timed out" if timed_out else "could not be reached"
                last = Unavailable(f"{method} {path} {what} after {attempt} attempt(s)")
                wait = self.backoff_seconds * 2 ** (attempt - 1)
            else:
                self._read_rate_limit(response)
                request_id = response.headers.get("X-Request-Id")
                log_event(
                    "api_call", method=method, path=path, status=response.status_code,
                    req=request_id, attempt=attempt, idempotency_key=idem,
                )  # fmt: skip
                if response.status_code < 400:
                    return response
                error = self._api_error(response)
                if response.status_code == 429:
                    wait = error.retry_after or self.backoff_seconds
                    if wait > self.max_wait_seconds:
                        raise error
                elif response.status_code >= 500:
                    wait = self.backoff_seconds * 2 ** (attempt - 1)
                else:
                    raise error  # 4xx: retrying would only replay it
                last = error
            if attempt < attempts:
                self.sleep(wait)
        raise last

    def _wait_for_rate_limit(self) -> None:
        state = self.rate_limit
        if state is None or state.remaining > 0:
            return
        elapsed = (self.clock.now() - state.seen_at).total_seconds()
        wait = min(state.reset_seconds - elapsed, self.max_wait_seconds)
        if wait > 0:
            log_event("rate_limit_wait", seconds=wait)
            self.sleep(wait)

    def _read_rate_limit(self, response: httpx.Response) -> None:
        try:
            self.rate_limit = RateLimitState(
                limit=int(response.headers["RateLimit-Limit"]),
                remaining=int(response.headers["RateLimit-Remaining"]),
                reset_seconds=float(response.headers["RateLimit-Reset"]),
                seen_at=self.clock.now(),
            )
        except (KeyError, ValueError):
            pass  # absent on unauthenticated responses; keep the last state we saw

    @staticmethod
    def _api_error(response: httpx.Response) -> ApiError:
        request_id = response.headers.get("X-Request-Id")
        code, message = "unknown", response.text[:200]
        try:
            error = loads(response.content)["error"]
            code, message = str(error["code"]), str(error["message"])
            request_id = request_id or error.get("request_id")
        except (ValueError, KeyError, TypeError):
            pass
        retry_after = None
        try:
            retry_after = float(response.headers["Retry-After"])
        except (KeyError, ValueError):
            pass
        return ApiError(response.status_code, code, message, request_id, retry_after)

    def _decision(self, response: httpx.Response) -> Decision:
        try:
            data = loads(response.content)
        except ValueError as error:
            raise SpendGuardError(
                "response is not valid JSON", response.headers.get("X-Request-Id")
            ) from error
        replayed = response.headers.get("Idempotency-Replayed") == "true"
        return self._parse_decision(data, response.headers.get("X-Request-Id"), replayed)

    @staticmethod
    def _parse_decision(
        data: Any, request_id: str | None = None, replayed: bool = False
    ) -> Decision:
        if not isinstance(data, dict):
            raise SpendGuardError("decision is not a JSON object", request_id)
        try:
            return Decision.model_validate({**data, "request_id": request_id, "replayed": replayed})
        except ValidationError as error:
            raise SpendGuardError(f"unreadable decision: {error}", request_id) from error
