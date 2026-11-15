"""Receive webhook events from the authorization API: verify them, re-read the object, then act.

An event is a POST with `Content-Type: application/jwt` and an ES256 JWT as the
body, signed with the same keys as verdicts. `WebhookReceiver.handle` runs:

1. Content type must be `application/jwt`.
2. Signature and issuer, as for a verdict, but requiring `iss, jti, iat, type,
   data` instead of `exp` and `nonce` (events have none). A verdict token fails
   here: it has no `type` or `data`.
3. A `sandbox-` kid is rejected unless sandbox is allowed.
4. `iat` more than 60 seconds in the future is rejected (it would otherwise
   dodge the age check), and so is an event older than 25 hours.
5. Duplicates (the same `jti`, which stays the same across retries) are
   acknowledged and not acted on again.
6. Before acting, the object is fetched with our own key. A genuine event from
   another organization verifies here too; its object is not found with our key,
   so it is acknowledged and ignored. A denied or expired review has no endpoint,
   so it is acted on only if one of our own authorization responses returned it.
7. The event is stored (append-only; the jti is the primary key, which is the
   dedupe), then acted on.

Answers: 200 when handled or ignored, 400 when the event fails a check, 503 when
the object couldn't be fetched (so the sender retries the identical token later).

What "act" means here: `decision.review_pending` notifies a human, because
a review that nobody sees is a payment that never happens (SPEC section 17.3).
"""

from __future__ import annotations

import sqlite3
import sys
import threading
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from fastapi import FastAPI, Request, Response

from spend_guard.client import SpendGuardClient
from spend_guard.clock import Clock, SystemClock
from spend_guard.errors import (
    ApiError,
    FutureIatError,
    SandboxKidError,
    SpendGuardError,
    StaleEventError,
    TokenFormatError,
    VerificationError,
)
from spend_guard.jwks import KeySet
from spend_guard.logs import log_event
from spend_guard.models import Decision
from spend_guard.verify import FUTURE_IAT_LEEWAY, decode_signed, is_int

EVENT_CLAIMS = ("iss", "jti", "iat", "type", "data")
MAX_EVENT_AGE = timedelta(hours=25)

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    jti TEXT PRIMARY KEY, type TEXT NOT NULL, iat INTEGER NOT NULL,
    received_at INTEGER NOT NULL, token TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
    BEGIN SELECT RAISE(ABORT, 'events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
    BEGIN SELECT RAISE(ABORT, 'events is append-only'); END;
"""


def notify_human(message: str) -> None:
    """The default way to reach a person: a clearly marked line on stderr, plus a log line.
    A real integration would page, email or post to a channel here."""
    print(f"\n*** HUMAN ACTION NEEDED *** {message}\n", file=sys.stderr, flush=True)
    log_event("human_notified", message=message)


def verify_event(
    token: str, *, jwks: KeySet, allow_sandbox: bool = False, clock: Clock | None = None
) -> dict[str, Any]:
    """Checks 2 to 4 above. Returns the claims, or raises a VerificationError subclass."""
    now = (clock or SystemClock()).now()
    header, claims = decode_signed(token, jwks, EVENT_CLAIMS)
    if not (is_int(claims["iat"]) and isinstance(claims["jti"], str)):
        raise TokenFormatError("iat must be an integer and jti a string")
    if not (isinstance(claims["type"], str) and isinstance(claims["data"], dict)):
        raise TokenFormatError("type must be a string and data an object")
    if header["kid"].startswith("sandbox-") and not allow_sandbox:
        raise SandboxKidError(f"sandbox key {header['kid']} on a production endpoint")
    now_ts = int(now.timestamp())
    if claims["iat"] > now_ts + FUTURE_IAT_LEEWAY:
        raise FutureIatError(f"event iat is {claims['iat'] - now_ts} seconds in the future")
    if now_ts - claims["iat"] > MAX_EVENT_AGE.total_seconds():
        raise StaleEventError("event is older than 25 hours")
    return claims


class NotOurs(Exception):
    """The event's object isn't found with our own key."""


class WebhookReceiver:
    def __init__(
        self,
        *,
        jwks: KeySet,
        client: SpendGuardClient,  # our own key, for re-reading objects; never the agent's
        is_our_review: Callable[[str], bool],
        notify: Callable[[str], None] = notify_human,
        on_approval: Callable[[Decision], None] | None = None,
        allow_sandbox: bool = False,
        clock: Clock | None = None,
        db_path: str = ":memory:",
    ) -> None:
        self.jwks = jwks
        self.client = client
        self.is_our_review = is_our_review
        self.notify = notify
        self.on_approval = on_approval
        self.allow_sandbox = allow_sandbox
        self.clock = clock or SystemClock()
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)

    def handle(self, body: bytes, content_type: str | None) -> tuple[int, str]:
        """Process one delivery. Returns (HTTP status, short reason)."""
        if (content_type or "").split(";")[0].strip().lower() != "application/jwt":
            return self._answer(400, "content type must be application/jwt")
        try:
            token = body.decode("ascii")
            event = verify_event(
                token, jwks=self.jwks, allow_sandbox=self.allow_sandbox, clock=self.clock
            )
        except (UnicodeDecodeError, VerificationError) as error:
            return self._answer(400, f"rejected: {error}")

        jti, event_type = event["jti"], event["type"]
        if self._seen(jti):
            return self._answer(200, "duplicate, already handled", jti, event_type)
        try:
            fetched = self._fetch(event)
        except NotOurs:
            fetched = None
            ours = False
        except SpendGuardError as error:
            # Not recorded, so the sender's retry (the identical token) is processed later.
            return self._answer(503, f"could not re-read the object: {error}", jti, event_type)
        else:
            ours = True

        if not self._record(event, token):
            return self._answer(200, "duplicate, already handled", jti, event_type)
        if not ours:
            return self._answer(200, "not one of our objects; ignored", jti, event_type)
        return self._answer(200, self._act(event, fetched), jti, event_type)

    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self._conn.execute("SELECT * FROM events")]

    # Steps

    def _fetch(self, event: dict[str, Any]) -> Any:
        """Re-read the object the event is about, with our own key. None when the event
        has no object to read (a ping, a denied or expired review, an unhandled type)."""
        event_type, data = event["type"], event["data"]
        try:
            if event_type == "decision.review_pending" or (
                event_type == "decision.resolved" and "decision" in data
            ):
                return self.client.get_decision(str(data.get("decision")))
            if event_type == "mandate.revoked":
                return self.client.get_mandate(str(data.get("mandate")))
        except ApiError as error:
            if error.status == 404:
                raise NotOurs from error
            raise
        return None

    def _act(self, event: dict[str, Any], fetched: Any) -> str:
        """Act on what we fetched, never on the event's own copy of the object."""
        event_type, data = event["type"], event["data"]
        if event_type == "decision.review_pending":
            decision: Decision = fetched
            if decision.verdict != "review" or decision.review is None:
                return f"decision {decision.decision} is not a pending review; ignored"
            request, review = decision.request, decision.review
            self.notify(
                f"Review {review.review} needs a decision from {review.waits_for}: "
                f"{request.amount} {request.currency} to {request.recipient} "
                f"({request.category}) by agent {request.agent}. Decision {decision.decision}. "
                f"Approve or deny with an org key before {review.expires_at.isoformat()}."
            )
            return "review sent to a person"

        if event_type == "decision.resolved" and fetched is not None:
            decision = fetched
            if decision.verdict != "allow" or decision.supersedes is None:
                return f"decision {decision.decision} is not an approval; ignored"
            self.notify(
                f"Review approved: decision {decision.decision} supersedes "
                f"{decision.supersedes}. It is valid until {decision.expires_at}."
            )
            if self.on_approval is not None:
                self.on_approval(decision)
            return "approval received"

        if event_type == "decision.resolved":  # a denied or expired review object
            review_id = data.get("review")
            if not isinstance(review_id, str) or not self.is_our_review(review_id):
                return "review is not one of ours; ignored"
            self.notify(f"Review {review_id} was {data.get('status')}. Nothing will be paid.")
            return f"review {data.get('status')}"

        if event_type == "mandate.revoked":
            mandate: dict[str, Any] = fetched
            self.notify(
                f"Mandate {mandate.get('mandate')} was revoked at {mandate.get('revoked_at')}. "
                "Requests under it now return deny_revoked."
            )
            return "revocation sent to a person"

        if event_type == "ping":
            return "ping"
        return f"event type {event_type} is not handled here; stored and acknowledged"

    def _seen(self, jti: str) -> bool:
        with self._lock:
            row = self._conn.execute("SELECT 1 FROM events WHERE jti = ?", (jti,)).fetchone()
        return row is not None

    def _record(self, event: dict[str, Any], token: str) -> bool:
        """Store the event. False if another delivery of it got there first."""
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO events VALUES (?, ?, ?, ?, ?) ON CONFLICT (jti) DO NOTHING",
                (
                    event["jti"], event["type"], event["iat"],
                    int(self.clock.now().timestamp()), token,
                ),
            )  # fmt: skip
        return cursor.rowcount == 1

    @staticmethod
    def _answer(
        status: int, reason: str, jti: str | None = None, event_type: str | None = None
    ) -> tuple[int, str]:
        log_event("webhook", status=status, evt=jti, type=event_type, reason=reason)
        return status, reason


def create_receiver_app(receiver: WebhookReceiver) -> FastAPI:
    """A one-route app to run the receiver over HTTP: POST /webhooks."""
    app = FastAPI(title="spend-guard webhook receiver")

    @app.post("/webhooks")
    async def webhooks(request: Request) -> Response:
        body = await request.body()
        status, reason = receiver.handle(body, request.headers.get("content-type"))
        return Response(reason, status_code=status, media_type="text/plain")

    return app
