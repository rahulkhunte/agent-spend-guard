"""The mock HTTP API. LOCAL MOCK, not a hosted service.

Every request under /v1 passes through `gateway` in this order:
1. a `req_` id, returned in X-Request-Id on every response
2. authentication: no key or an unknown key is 401, on any path
3. the per-key rate limit, with RateLimit-* headers on every authenticated response
4. injected faults (authorizations only)
5. the route. POST routes go through `run_post`, which applies the idempotency rules.

Routes are thin: validation is in models.py and behaviour in engine.py.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import random
import threading
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from typing import Any, Literal, TypeVar

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from mock_api.engine import Engine
from mock_api.errors import ApiError, error_body
from mock_api.ids import key_hash, new_id
from mock_api.models import (
    AgentCreate,
    AuthorizationRequest,
    EnforcementSet,
    FaultsUpdate,
    MandateCreate,
    WebhookCreate,
    describe,
)
from mock_api.ratelimit import SlidingWindow
from mock_api.settings import Faults, Settings
from mock_api.signing import Signer
from mock_api.store import Store, ts
from mock_api.webhooks import Sender, Webhooks, http_sender
from spend_guard.clock import Clock, SystemClock
from spend_guard.jsonutil import dumps, loads

BANNER = "LOCAL MOCK: a reference authorization API, not a hosted service"
JWKS_PATH = "/.well-known/jwks.json"
MAX_BODY_BYTES = 64 * 1024
MAX_IDEMPOTENCY_KEY = 255
IDEMPOTENCY_WINDOW = 24 * 3600
NOT_STORED = {401, 403, 429}  # plus every 5xx

M = TypeVar("M", bound=BaseModel)

log = logging.getLogger("mock_api")


@dataclass(frozen=True)
class Principal:
    kind: Literal["org", "agent"]
    key_hash: str
    agent: str | None = None


class MockState:
    """Everything one running mock holds. One lock serializes all reads and writes."""

    def __init__(self, settings: Settings, clock: Clock, sender: Sender) -> None:
        self.settings = settings
        self.clock = clock
        self.faults: Faults = settings.faults
        self.rng = random.Random(settings.fault_seed)
        self.lock = threading.Lock()
        self.org_key_hash = key_hash(settings.org_key)
        self.store = Store(settings.db_path, ts(clock.now()))
        self.signer = Signer(f"sandbox-mock-{clock.now():%Y-%m-%d}")
        self.webhooks = Webhooks(self.store, self.signer, clock, self.lock, sender)
        self.engine = Engine(self.store, self.signer, clock, self.webhooks)
        self.limiter = SlidingWindow(settings.rate_limit, clock)

    def tick(self) -> None:
        """One background pass: close expired reviews, then deliver due webhooks."""
        with self.lock:
            self.engine.expire_reviews()
        self.webhooks.deliver_due()


class DecimalJSONResponse(Response):
    """JSON with Decimal amounts written as exact numbers."""

    media_type = "application/json"

    def render(self, content: Any) -> bytes:
        return dumps(content).encode()


def error_response(error: ApiError, request_id: str) -> Response:
    body = error_body(error.code, error.message, request_id)
    return DecimalJSONResponse(body, status_code=error.status, headers=error.headers)


def log_json(**fields: Any) -> None:
    """Structured logs carry req_ and dec_ ids so one run can be traced end to end."""
    log.info(json.dumps(fields))


def authenticate(state: MockState, header: str | None) -> Principal | None:
    if not header or not header.startswith("Bearer "):
        return None
    digest = key_hash(header.removeprefix("Bearer ").strip())
    if hmac.compare_digest(digest, state.org_key_hash):
        return Principal("org", digest)
    with state.lock:
        agent = state.store.agent_for_key(digest)
    return Principal("agent", digest, agent) if agent else None


def require_org(principal: Principal) -> None:
    if principal.kind != "org":
        raise ApiError(403, "This endpoint needs an organization key")


async def apply_faults(state: MockState, request: Request) -> Response | None:
    """Injected failures for POST /v1/authorizations. They happen before the endpoint runs,
    so no decision is created and nothing is stored under the Idempotency-Key."""
    if request.method != "POST" or request.url.path != "/v1/authorizations":
        return None
    faults = state.faults
    request_id = request.state.request_id
    if faults.latency_ms:
        await asyncio.sleep(faults.latency_ms / 1000)
    if faults.rate_limit_burst > 0:
        faults.rate_limit_burst -= 1
        retry_after = {"Retry-After": str(faults.retry_after_seconds)}
        error = ApiError(
            429, "Rate limit reached for this key; retry after Retry-After", retry_after
        )
        return error_response(error, request_id)
    if state.rng.random() < faults.timeout_rate:
        await asyncio.sleep(faults.timeout_seconds)
        return error_response(ApiError(503, "injected timeout (mock fault)"), request_id)
    if state.rng.random() < faults.error_rate:
        return error_response(ApiError(500, "injected server error (mock fault)"), request_id)
    return None


async def read_body(request: Request) -> bytes:
    """Refused here means refused before the endpoint: never stored for idempotency."""
    length = request.headers.get("Content-Length")
    if length is not None:
        if not length.isdigit():
            raise ApiError(400, "invalid Content-Length")
        if int(length) > MAX_BODY_BYTES:
            raise ApiError(400, "request body is over 64 KB")
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise ApiError(400, "request body is over 64 KB")
    return body


def parse_object(body: bytes) -> dict[str, Any]:
    try:
        data = loads(body)
    except (ValueError, RecursionError) as error:  # RecursionError: absurdly deep nesting
        raise ApiError(400, "body is not valid JSON") from error
    if not isinstance(data, dict):
        raise ApiError(400, "body must be a JSON object")
    return data


def validate(model: type[M], body: bytes) -> M:
    try:
        return model.model_validate(parse_object(body))
    except ValidationError as error:
        raise ApiError(400, describe(error)) from error


def parse_query_date(value: str | None, name: str) -> datetime:
    if value is None:
        raise ApiError(400, f"{name} is required")
    try:
        day = date.fromisoformat(value)
    except ValueError as error:
        raise ApiError(400, f"{name} must be a date, YYYY-MM-DD") from error
    return datetime(day.year, day.month, day.day, tzinfo=UTC)


Handler = Callable[[bytes], tuple[int, dict[str, Any]]]


def create_app(
    settings: Settings, clock: Clock | None = None, sender: Sender = http_sender
) -> FastAPI:
    state = MockState(settings, clock or SystemClock(), sender)

    async def tick_forever() -> None:
        while True:
            await asyncio.sleep(settings.webhook_interval)
            await asyncio.to_thread(state.tick)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        log.warning(BANNER)
        task = asyncio.create_task(tick_forever()) if settings.webhook_interval > 0 else None
        yield
        if task is not None:
            task.cancel()

    app = FastAPI(title=BANNER, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.mock = state

    async def run(request: Request, call_next: Callable[..., Any]) -> Response:
        """Any crash inside an endpoint still answers in the error envelope."""
        try:
            response: Response = await call_next(request)
        except Exception:
            log.exception("unhandled error in the mock")
            return error_response(ApiError(500, "internal error"), request.state.request_id)
        return response

    @app.middleware("http")
    async def gateway(request: Request, call_next: Callable[..., Any]) -> Response:
        request_id = new_id("req_", 16)
        request.state.request_id = request_id
        path = request.url.path
        # A key is needed on every path, including ones that don't exist. The one
        # exception is the public key set, which verifiers read without a key.
        if path != JWKS_PATH:
            principal = authenticate(state, request.headers.get("Authorization"))
            if principal is None:
                response = error_response(ApiError(401, "Missing or unknown key"), request_id)
            else:
                request.state.principal = principal
                allowed, limit_headers = state.limiter.hit(principal.key_hash)
                if not allowed:
                    message = "Rate limit reached for this key; retry after Retry-After"
                    retry_after = {
                        "Retry-After": str(max(1, int(limit_headers["RateLimit-Reset"])))
                    }
                    response = error_response(ApiError(429, message, retry_after), request_id)
                else:
                    response = await apply_faults(state, request) or await run(request, call_next)
                response.headers.update(limit_headers)
        else:
            response = await run(request, call_next)
        response.headers["X-Request-Id"] = request_id
        log_json(req=request_id, method=request.method, path=path, status=response.status_code)
        return response

    @app.exception_handler(ApiError)
    async def api_error(request: Request, error: ApiError) -> Response:
        return error_response(error, request.state.request_id)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, error: StarletteHTTPException) -> Response:
        if error.status_code == 405:  # SPEC section 12: 400, with no Allow header
            api = ApiError(400, f"{request.method} is not supported on {request.url.path}")
        elif error.status_code == 404:  # includes GET /v1/reviews, which does not exist
            api = ApiError(404, f"no such path {request.url.path}")
        else:
            api = ApiError(error.status_code, str(error.detail))
        return error_response(api, request.state.request_id)

    async def run_post(request: Request, handler: Handler, *, org_only: bool = False) -> Response:
        """Idempotency for every POST.

        Same API key + Idempotency-Key + identical request (endpoint and body) within
        24 h: the stored result, with Idempotency-Replayed: true. Same key, a different
        body or a different endpoint: 409. The endpoint's
        own results are stored unless 401, 403, 429 or 5xx. Refusals before the endpoint
        (wrong key class, oversized body, key over 255 chars) raise and are never stored.
        """
        principal: Principal = request.state.principal
        if org_only:
            require_org(principal)
        body = await read_body(request)
        idem_key = request.headers.get("Idempotency-Key")
        if idem_key is not None and len(idem_key) > MAX_IDEMPOTENCY_KEY:
            raise ApiError(400, "Idempotency-Key is over 255 characters")
        # R-077: byte-for-byte, and tied to the endpoint, so a key used on one call
        # can never replay the stored result of a different call.
        request_line = f"{request.method} {request.url.path}\n".encode()
        body_hash = hashlib.sha256(request_line + body).hexdigest()

        with state.lock:
            now = ts(state.clock.now())
            if idem_key is not None:
                stored = state.store.idempotent_result(
                    principal.key_hash, idem_key, since=now - IDEMPOTENCY_WINDOW
                )
                if stored is not None:
                    if stored["body_hash"] != body_hash:
                        raise ApiError(
                            409, "Idempotency-Key was already used with a different request"
                        )
                    return DecimalJSONResponse(
                        loads(stored["response"]),
                        status_code=stored["status"],
                        headers={"Idempotency-Replayed": "true"},
                    )
            try:
                status, payload = handler(body)
            except ApiError as error:
                status = error.status
                payload = error_body(error.code, error.message, request.state.request_id)
            if idem_key is not None and status < 500 and status not in NOT_STORED:
                state.store.add_idempotent_result(
                    principal.key_hash, idem_key, body_hash, status, dumps(payload), now
                )
        return DecimalJSONResponse(payload, status_code=status)

    # Agents

    @app.post("/v1/agents")
    async def post_agent(request: Request) -> Response:
        return await run_post(
            request,
            lambda body: (201, state.engine.create_agent(validate(AgentCreate, body))),
            org_only=True,
        )

    @app.post("/v1/agents/{agent_id}/disable")
    async def post_disable(request: Request, agent_id: str) -> Response:
        return await run_post(
            request,
            lambda _: (200, state.engine.set_agent_status(agent_id, "disabled")),
            org_only=True,
        )

    @app.post("/v1/agents/{agent_id}/enable")
    async def post_enable(request: Request, agent_id: str) -> Response:
        return await run_post(
            request,
            lambda _: (200, state.engine.set_agent_status(agent_id, "active")),
            org_only=True,
        )

    # Mandates

    @app.post("/v1/mandates")
    async def post_mandate(request: Request) -> Response:
        return await run_post(
            request,
            lambda body: (201, state.engine.create_mandate(validate(MandateCreate, body))),
            org_only=True,
        )

    @app.get("/v1/mandates/{mandate_id}")
    async def get_mandate(request: Request, mandate_id: str) -> Response:
        require_org(request.state.principal)
        with state.lock:
            return DecimalJSONResponse(state.engine.get_mandate(mandate_id))

    @app.post("/v1/mandates/{mandate_id}/revoke")
    async def post_revoke(request: Request, mandate_id: str) -> Response:
        return await run_post(
            request, lambda _: (200, state.engine.revoke_mandate(mandate_id)), org_only=True
        )

    # Authorizations, decisions and reviews

    @app.post("/v1/authorizations")
    async def post_authorization(request: Request) -> Response:
        principal: Principal = request.state.principal

        def handle(body: bytes) -> tuple[int, dict[str, Any]]:
            spend = validate(AuthorizationRequest, body)
            if principal.kind == "org":
                if spend.agent is None:
                    raise ApiError(400, "agent is required on an organization key")
                if state.store.agent(spend.agent) is None:
                    raise ApiError(400, f"unknown agent {spend.agent}")
                agent = spend.agent
            else:
                agent = principal.agent  # the agent comes from the key; a body `agent` is ignored
            assert agent is not None
            decision = state.engine.authorize(
                agent, spend, forced_verdict=state.faults.forced_verdict
            )
            log_json(
                req=request.state.request_id,
                decision=decision["decision"],
                verdict=decision["verdict"],
                agent=agent,
                mode=decision["mode"],
            )
            return 201, decision  # 201 whatever the verdict: a denial is not an error

        return await run_post(request, handle)

    @app.get("/v1/decisions/{decision_id}")
    async def get_decision(request: Request, decision_id: str) -> Response:
        principal: Principal = request.state.principal
        with state.lock:
            decision = state.store.decision(decision_id)
        not_yours = (
            principal.kind == "agent"
            and decision is not None
            and (decision["request"]["agent"] != principal.agent)
        )
        if decision is None or not_yours:  # "not yours" is reported as absent, not forbidden
            raise ApiError(404, f"no decision {decision_id}")
        return DecimalJSONResponse(decision)

    @app.post("/v1/reviews/{review_id}/approve")
    async def post_approve(request: Request, review_id: str) -> Response:
        return await run_post(
            request, lambda _: (201, state.engine.approve_review(review_id)), org_only=True
        )

    @app.post("/v1/reviews/{review_id}/deny")
    async def post_deny(request: Request, review_id: str) -> Response:
        return await run_post(
            request, lambda _: (200, state.engine.deny_review(review_id)), org_only=True
        )

    # Enforcement

    @app.get("/v1/enforcement")
    async def get_enforcement(request: Request) -> Response:
        require_org(request.state.principal)
        with state.lock:
            return DecimalJSONResponse(state.engine.enforcement_view())

    @app.post("/v1/enforcement")
    async def post_enforcement(request: Request) -> Response:
        return await run_post(
            request,
            lambda body: (200, state.engine.set_mode(validate(EnforcementSet, body).mode)),
            org_only=True,
        )

    # Webhooks and exports

    @app.post("/v1/webhooks")
    async def post_webhook(request: Request) -> Response:
        return await run_post(
            request,
            lambda body: (201, state.engine.create_webhook(validate(WebhookCreate, body))),
            org_only=True,
        )

    @app.get("/v1/exports/records")
    async def export_records(request: Request) -> Response:
        """NDJSON, one decision record per line. `from` inclusive, `to` exclusive."""
        require_org(request.state.principal)
        start = parse_query_date(request.query_params.get("from"), "from")
        end = parse_query_date(request.query_params.get("to"), "to")
        with state.lock:
            records = state.store.decisions_between(ts(start), ts(end))
        lines = (dumps(record) + "\n" for record in records)
        return StreamingResponse(lines, media_type="application/x-ndjson")

    # Public key set (SPEC section 15.1)

    @app.get(JWKS_PATH)
    async def jwks() -> Response:
        headers = {"Cache-Control": "max-age=300", "Access-Control-Allow-Origin": "*"}
        return JSONResponse(state.signer.jwks(), headers=headers)

    # Mock-only controls, not part of the spec'd API

    @app.get("/_mock/faults")
    async def get_faults(request: Request) -> Response:
        require_org(request.state.principal)
        return JSONResponse(asdict(state.faults))

    @app.post("/_mock/faults")
    async def post_faults(request: Request) -> Response:
        require_org(request.state.principal)
        update = validate(FaultsUpdate, await read_body(request))
        for name, value in update.model_dump(exclude_none=True).items():
            setattr(state.faults, name, value)
        return JSONResponse(asdict(state.faults))

    return app
