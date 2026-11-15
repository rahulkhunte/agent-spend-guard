"""SQLite storage. Every table is append-only.

Nothing is ever updated or deleted: triggers make SQLite refuse it. A change of
state is a new row, so current state is "the latest row":
- an agent's status is its latest `agent_status` row
- a revocation is a row in `mandate_revocations`
- a review's outcome is a row in `review_outcomes`
- the enforcement mode is the latest `enforcement` row

The decision log works the same way: a correction is a new record, never a rewrite.
Times are stored as whole UTC epoch seconds.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from spend_guard.jsonutil import dumps, loads

TABLES = """
CREATE TABLE IF NOT EXISTS org (created_on TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash TEXT PRIMARY KEY, kind TEXT NOT NULL, agent TEXT, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS agents (
    agent TEXT PRIMARY KEY, body TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS agent_status (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, agent TEXT NOT NULL, status TEXT NOT NULL,
    at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS mandates (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, mandate TEXT UNIQUE NOT NULL, agent TEXT NOT NULL,
    currency TEXT NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS mandate_revocations (
    mandate TEXT PRIMARY KEY, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS decisions (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, decision TEXT UNIQUE NOT NULL, agent TEXT NOT NULL,
    mandate TEXT, verdict TEXT NOT NULL, amount TEXT NOT NULL, issued_at INTEGER NOT NULL,
    body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reviews (
    review TEXT PRIMARY KEY, decision TEXT NOT NULL, waits_for TEXT NOT NULL,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS review_outcomes (
    review TEXT PRIMARY KEY, status TEXT NOT NULL, decision TEXT, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS enforcement (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, mode TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS idempotency (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, key_hash TEXT NOT NULL, idem_key TEXT NOT NULL,
    body_hash TEXT NOT NULL, status INTEGER NOT NULL, response TEXT NOT NULL,
    created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS webhook_endpoints (
    webhook TEXT PRIMARY KEY, body TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS webhook_events (
    event TEXT PRIMARY KEY, type TEXT NOT NULL, token TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    event TEXT NOT NULL, webhook TEXT NOT NULL, url TEXT NOT NULL,
    PRIMARY KEY (event, webhook));
CREATE TABLE IF NOT EXISTS webhook_attempts (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, webhook TEXT NOT NULL,
    status INTEGER NOT NULL, at INTEGER NOT NULL);
"""

APPEND_ONLY_TABLES = [
    "org", "api_keys", "agents", "agent_status", "mandates", "mandate_revocations",
    "decisions", "reviews", "review_outcomes", "enforcement", "idempotency",
    "webhook_endpoints", "webhook_events", "webhook_deliveries", "webhook_attempts",
]  # fmt: skip


def ts(moment: datetime) -> int:
    return int(moment.timestamp())


def iso(epoch_seconds: int) -> str:
    return datetime.fromtimestamp(epoch_seconds, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_schema(conn: sqlite3.Connection, now: int) -> None:
    conn.executescript(TABLES)
    for table in APPEND_ONLY_TABLES:
        for action in ("UPDATE", "DELETE"):
            conn.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_no_{action.lower()} "
                f"BEFORE {action} ON {table} "
                f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END"
            )
    if conn.execute("SELECT COUNT(*) FROM org").fetchone()[0] == 0:
        conn.execute("INSERT INTO org VALUES (?)", (iso(now)[:10],))
    if conn.execute("SELECT COUNT(*) FROM enforcement").fetchone()[0] == 0:
        # Sandbox starts in enforce; production would start in observe.
        conn.execute("INSERT INTO enforcement (mode, at) VALUES ('enforce', ?)", (now,))


class Store:
    def __init__(self, path: str, now: int) -> None:
        # Autocommit mode; multi-row changes use transaction(). The app serializes access.
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        create_schema(self.conn, now)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self.conn.execute("COMMIT")

    def _one(self, sql: str, *args: Any) -> sqlite3.Row | None:
        return self.conn.execute(sql, args).fetchone()

    def _body(self, sql: str, *args: Any) -> dict[str, Any] | None:
        row = self._one(sql, *args)
        return loads(row["body"]) if row else None

    # Organization and keys

    def org_created_on(self) -> str:
        return self._one("SELECT created_on FROM org")["created_on"]

    def add_key(self, key_hash: str, kind: str, agent: str | None, at: int) -> None:
        self.conn.execute("INSERT INTO api_keys VALUES (?, ?, ?, ?)", (key_hash, kind, agent, at))

    def agent_for_key(self, key_hash: str) -> str | None:
        row = self._one(
            "SELECT agent FROM api_keys WHERE key_hash = ? AND kind = 'agent'", key_hash
        )
        return row["agent"] if row else None

    # Agents

    def add_agent(self, agent: str, body: dict[str, Any], at: int) -> None:
        self.conn.execute("INSERT INTO agents VALUES (?, ?, ?)", (agent, dumps(body), at))

    def agent(self, agent: str) -> dict[str, Any] | None:
        return self._body("SELECT body FROM agents WHERE agent = ?", agent)

    def add_agent_status(self, agent: str, status: str, at: int) -> None:
        self.conn.execute(
            "INSERT INTO agent_status (agent, status, at) VALUES (?, ?, ?)", (agent, status, at)
        )

    def agent_status(self, agent: str) -> str | None:
        row = self._one(
            "SELECT status FROM agent_status WHERE agent = ? ORDER BY seq DESC LIMIT 1", agent
        )
        return row["status"] if row else None

    # Mandates

    def add_mandate(self, mandate: dict[str, Any], at: int) -> None:
        self.conn.execute(
            "INSERT INTO mandates (mandate, agent, currency, body, created_at) VALUES (?,?,?,?,?)",
            (
                mandate["mandate"],
                mandate["agent"],
                mandate["limits"]["currency"],
                dumps(mandate),
                at,
            ),
        )

    def mandate(self, mandate: str) -> dict[str, Any] | None:
        return self._body("SELECT body FROM mandates WHERE mandate = ?", mandate)

    def mandates_for(self, agent: str, currency: str) -> list[dict[str, Any]]:
        """Every mandate the agent has held in this currency, oldest first.

        Revoked and expired ones are included: the engine weighs them all.
        `=` on TEXT is an exact, case-sensitive comparison in SQLite.
        """
        rows = self.conn.execute(
            "SELECT body FROM mandates WHERE agent = ? AND currency = ? ORDER BY seq",
            (agent, currency),
        )
        return [loads(row["body"]) for row in rows]

    def add_revocation(self, mandate: str, at: int) -> None:
        self.conn.execute("INSERT INTO mandate_revocations VALUES (?, ?)", (mandate, at))

    def revoked_at(self, mandate: str) -> int | None:
        row = self._one("SELECT at FROM mandate_revocations WHERE mandate = ?", mandate)
        return row["at"] if row else None

    # Decisions (the log)

    def add_decision(self, decision: dict[str, Any], issued_at: int) -> None:
        request = decision["request"]
        self.conn.execute(
            "INSERT INTO decisions (decision, agent, mandate, verdict, amount, issued_at, body) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                decision["decision"],
                request["agent"],
                decision.get("mandate"),
                decision["verdict"],
                dumps(request["amount"]),
                issued_at,
                dumps(decision),
            ),
        )

    def decision(self, decision: str) -> dict[str, Any] | None:
        return self._body("SELECT body FROM decisions WHERE decision = ?", decision)

    def allowed_total(self, mandate: str, since: int) -> Decimal:
        """Sum of `allow` amounts under a mandate issued after `since`. Summed as Decimal."""
        rows = self.conn.execute(
            "SELECT amount FROM decisions "
            "WHERE mandate = ? AND verdict = 'allow' AND issued_at > ?",
            (mandate, since),
        )
        return sum((Decimal(row["amount"]) for row in rows), Decimal(0))

    def decision_count(self, agent: str, since: int) -> int:
        """Decisions for an agent issued after `since`. Errors and replays create no decision."""
        row = self._one(
            "SELECT COUNT(*) AS n FROM decisions WHERE agent = ? AND issued_at > ?", agent, since
        )
        return row["n"]

    def decisions_between(self, start: int, end: int) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT body FROM decisions WHERE issued_at >= ? AND issued_at < ? ORDER BY seq",
            (start, end),
        )
        return [loads(row["body"]) for row in rows]

    # Reviews

    def add_review(self, review: str, decision: str, waits_for: str, at: int, expires: int) -> None:
        self.conn.execute(
            "INSERT INTO reviews VALUES (?, ?, ?, ?, ?)", (review, decision, waits_for, at, expires)
        )

    def review(self, review: str) -> sqlite3.Row | None:
        return self._one("SELECT * FROM reviews WHERE review = ?", review)

    def add_review_outcome(self, review: str, status: str, decision: str | None, at: int) -> None:
        self.conn.execute(
            "INSERT INTO review_outcomes VALUES (?, ?, ?, ?)", (review, status, decision, at)
        )

    def review_outcome(self, review: str) -> str | None:
        row = self._one("SELECT status FROM review_outcomes WHERE review = ?", review)
        return row["status"] if row else None

    def reviews_due_to_expire(self, now: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM reviews WHERE expires_at <= ? "
            "AND review NOT IN (SELECT review FROM review_outcomes)",
            (now,),
        ).fetchall()

    # Enforcement

    def add_mode(self, mode: str, at: int) -> None:
        self.conn.execute("INSERT INTO enforcement (mode, at) VALUES (?, ?)", (mode, at))

    def mode(self) -> tuple[str, int]:
        row = self._one("SELECT mode, at FROM enforcement ORDER BY seq DESC LIMIT 1")
        return row["mode"], row["at"]

    # Idempotency

    def add_idempotent_result(
        self, key_hash: str, idem_key: str, body_hash: str, status: int, response: str, at: int
    ) -> None:
        self.conn.execute(
            "INSERT INTO idempotency (key_hash, idem_key, body_hash, status, response, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (key_hash, idem_key, body_hash, status, response, at),
        )

    def idempotent_result(self, key_hash: str, idem_key: str, since: int) -> sqlite3.Row | None:
        """The stored result for this API key and Idempotency-Key, if newer than `since`.

        Scoped by the API key's hash, so another key using the same Idempotency-Key
        never sees it.
        """
        return self._one(
            "SELECT * FROM idempotency WHERE key_hash = ? AND idem_key = ? AND created_at > ? "
            "ORDER BY seq DESC LIMIT 1",
            key_hash,
            idem_key,
            since,
        )

    # Webhooks

    def add_webhook(self, webhook: dict[str, Any], at: int) -> None:
        self.conn.execute(
            "INSERT INTO webhook_endpoints VALUES (?, ?, ?)",
            (webhook["webhook"], dumps(webhook), at),
        )

    def webhooks(self) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT body FROM webhook_endpoints ORDER BY created_at")
        return [loads(row["body"]) for row in rows]

    def add_event(self, event: str, event_type: str, token: str, at: int) -> None:
        self.conn.execute(
            "INSERT INTO webhook_events VALUES (?, ?, ?, ?)", (event, event_type, token, at)
        )

    def add_delivery(self, event: str, webhook: str, url: str) -> None:
        self.conn.execute("INSERT INTO webhook_deliveries VALUES (?, ?, ?)", (event, webhook, url))

    def add_attempt(self, event: str, webhook: str, status: int, at: int) -> None:
        self.conn.execute(
            "INSERT INTO webhook_attempts (event, webhook, status, at) VALUES (?, ?, ?, ?)",
            (event, webhook, status, at),
        )

    def undelivered(self) -> list[sqlite3.Row]:
        """Deliveries with no 2xx attempt yet, with their attempt count and last attempt time."""
        return self.conn.execute(
            """
            SELECT d.event, d.webhook, d.url, e.token, e.created_at,
                   COUNT(a.seq) AS attempts, MAX(a.at) AS last_at
            FROM webhook_deliveries d
            JOIN webhook_events e ON e.event = d.event
            LEFT JOIN webhook_attempts a ON a.event = d.event AND a.webhook = d.webhook
            GROUP BY d.event, d.webhook
            HAVING SUM(CASE WHEN a.status BETWEEN 200 AND 299 THEN 1 ELSE 0 END) = 0
            ORDER BY e.created_at, e.rowid
            """
        ).fetchall()
