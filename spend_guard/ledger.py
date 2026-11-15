"""The gate's own record of every payment attempt, in append-only SQLite.

Two tables:
- `attempts`: one row per call to the gate, whatever happened, linked to the
  `dec_` id (the join key with the decision log) and the `req_` id when there
  is one. The raw verdict token is kept next to the record, and `attempt` is
  the number in the `Idempotency-Key` the gate sent (`<order_id>:<attempt>`).
- `claims`: at most one row per order. The gate inserts it, atomically, before
  calling the provider, so concurrent calls for one order can pay only once.

Like the decision log, nothing is ever updated or deleted; triggers refuse it.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from spend_guard.models import PaymentResult, PaymentStatus

TABLES = ["attempts", "claims"]
SCHEMA = """
CREATE TABLE IF NOT EXISTS attempts (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, order_id TEXT NOT NULL,
    status TEXT NOT NULL, decision TEXT, verdict TEXT, mode TEXT, reason TEXT,
    request_id TEXT, review TEXT, payment TEXT, would_have_blocked INTEGER NOT NULL,
    detail TEXT NOT NULL, verdict_token TEXT, attempt INTEGER);
CREATE TABLE IF NOT EXISTS claims (
    order_id TEXT PRIMARY KEY, decision TEXT NOT NULL, at INTEGER NOT NULL);
"""


@dataclass(frozen=True)
class LastAttempt:
    """The latest attempt the gate sent to the API for an order."""

    number: int
    status: str
    verdict: str | None
    decision: str | None


class Ledger:
    def __init__(self, db_path: str = ":memory:") -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        for table in TABLES:
            for action in ("UPDATE", "DELETE"):
                self._conn.execute(
                    f"CREATE TRIGGER IF NOT EXISTS {table}_no_{action.lower()} "
                    f"BEFORE {action} ON {table} "
                    f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END"
                )

    def record(
        self,
        result: PaymentResult,
        at: datetime,
        verdict_token: str | None,
        attempt: int | None = None,
    ) -> None:
        """`attempt` is None when no authorization was sent (an approval read, or an order
        already paid)."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO attempts (at, order_id, status, decision, verdict, mode, reason, "
                "request_id, review, payment, would_have_blocked, detail, verdict_token, "
                "attempt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    int(at.timestamp()), result.order_id, result.status.value, result.decision,
                    result.verdict, result.mode, result.reason, result.request_id, result.review,
                    result.payment, int(result.would_have_blocked), result.detail, verdict_token,
                    attempt,
                ),
            )  # fmt: skip

    def claim(self, order_id: str, decision: str, at: datetime) -> bool:
        """Reserve the order for payment. True for exactly one caller per order, ever."""
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO claims VALUES (?, ?, ?) ON CONFLICT (order_id) DO NOTHING",
                (order_id, decision, int(at.timestamp())),
            )
            return cursor.rowcount == 1

    def is_claimed(self, order_id: str) -> bool:
        with self._lock:
            row = self._conn.execute("SELECT 1 FROM claims WHERE order_id = ?", (order_id,))
            return row.fetchone() is not None

    def last_attempt(self, order_id: str) -> LastAttempt | None:
        """The latest row for this order that came from an authorization request."""
        with self._lock:
            row = self._conn.execute(
                "SELECT attempt, status, verdict, decision FROM attempts "
                "WHERE order_id = ? AND attempt IS NOT NULL ORDER BY seq DESC LIMIT 1",
                (order_id,),
            ).fetchone()
        if row is None:
            return None
        return LastAttempt(row["attempt"], row["status"], row["verdict"], row["decision"])

    def first_seen(self, decision: str) -> datetime | None:
        """When the gate first recorded this decision. A replayed decision keeps its first time."""
        with self._lock:
            row = self._conn.execute(
                "SELECT MIN(at) AS at FROM attempts WHERE decision = ?", (decision,)
            ).fetchone()
        return datetime.fromtimestamp(row["at"], UTC) if row["at"] is not None else None

    def has_review(self, review: str) -> bool:
        """Did one of this gate's own authorization responses return this `rev_` id?"""
        with self._lock:
            row = self._conn.execute("SELECT 1 FROM attempts WHERE review = ?", (review,))
            return row.fetchone() is not None

    def pending_review(self, order_id: str) -> str | None:
        """The `dec_` id of this order's latest `review` decision, if one was recorded."""
        with self._lock:
            row = self._conn.execute(
                "SELECT decision FROM attempts WHERE order_id = ? AND status = ? "
                "ORDER BY seq DESC LIMIT 1",
                (order_id, PaymentStatus.PENDING_REVIEW.value),
            ).fetchone()
        return row["decision"] if row else None

    def attempts(self, order_id: str | None = None) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM attempts", ()
        if order_id is not None:
            sql, args = sql + " WHERE order_id = ?", (order_id,)
        with self._lock:
            return [dict(row) for row in self._conn.execute(sql + " ORDER BY seq", args)]
