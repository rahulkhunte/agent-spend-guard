"""Webhook events: signed once when they happen, then delivered with the identical token
until an endpoint answers 2xx or 24 hours pass."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

import httpx

from mock_api.ids import new_id
from mock_api.signing import ISSUER, Signer
from mock_api.store import Store, ts
from spend_guard.clock import Clock

RETRY_WINDOW = 24 * 3600
MAX_BACKOFF = 3600

Sender = Callable[[str, str], int]  # (url, token) -> HTTP status, or 0 if unreachable


def http_sender(url: str, token: str) -> int:
    try:
        response = httpx.post(
            url, content=token, headers={"Content-Type": "application/jwt"}, timeout=5
        )
        return response.status_code
    except httpx.HTTPError:
        return 0


def next_attempt_due(attempts: int, last_attempt_at: int) -> int:
    """R-134: wait 1 s after the first failure, then 2, 4, 8... capped at 1 hour."""
    return last_attempt_at + min(2 ** (attempts - 1), MAX_BACKOFF)


class Webhooks:
    def __init__(
        self, store: Store, signer: Signer, clock: Clock, lock: threading.Lock, sender: Sender
    ) -> None:
        self.store = store
        self.signer = signer
        self.clock = clock
        self.lock = lock
        self.sender = sender

    def emit(self, event_type: str, data: dict[str, Any]) -> str:
        """Sign the event once and queue it for every endpoint subscribed to its type.

        Event tokens carry iss, jti, iat, type and data: no exp and no nonce, so a
        verdict check that requires those claims can never accept one.
        Called by the engine, which already holds the lock.
        """
        event_id = new_id("evt_")
        now = ts(self.clock.now())
        claims = {"iss": ISSUER, "jti": event_id, "iat": now, "type": event_type, "data": data}
        self.store.add_event(event_id, event_type, self.signer.sign(claims), now)
        for endpoint in self.store.webhooks():
            if event_type in endpoint["events"]:
                self.store.add_delivery(event_id, endpoint["webhook"], endpoint["url"])
        return event_id

    def deliver_due(self) -> int:
        """Attempt every delivery that is due. Returns how many attempts were made."""
        with self.lock:
            now = ts(self.clock.now())
            due = [row for row in self.store.undelivered() if self._is_due(row, now)]
        for row in due:
            status = self.sender(row["url"], row["token"])  # outside the lock: network call
            with self.lock:
                self.store.add_attempt(row["event"], row["webhook"], status, ts(self.clock.now()))
        return len(due)

    @staticmethod
    def _is_due(row: Any, now: int) -> bool:
        if now > row["created_at"] + RETRY_WINDOW:
            return False  # dropped from delivery
        if row["attempts"] == 0:
            return True
        return now >= next_attempt_due(row["attempts"], row["last_at"])
