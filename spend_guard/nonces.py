"""Where accepted nonces are remembered, so an approval is accepted at most once.

The rules for this store (SPEC section 16.3):
- record a nonce only after every other check has passed
- record it atomically (set-if-absent): check-then-set as two steps is a race
- keep it at least until the token's `exp` plus clock skew, and never less than 600 s
- share it across every instance that can accept the same verdict

`add` records several keys in one atomic step (a verdict's nonce, and for a
review approval the review it supersedes): either all are recorded, or none.

Unlike the ledger, this store is a cache, not a record: expired entries are
deleted. The record of what was accepted is the ledger, which keeps the token.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Protocol


class NonceStore(Protocol):
    def add(self, entries: Mapping[str, int], now: datetime) -> str | None:
        """Record every key with its time-to-live in seconds, atomically, unless one of them
        is already recorded and not yet expired. Returns None when all were recorded, or
        the first key already present, in which case nothing was recorded."""
        ...

    def seen(self, key: str, now: datetime) -> bool:
        """Is this key recorded and not yet expired?"""
        ...


class SqliteNonceStore:
    """SQLite, `INSERT ... ON CONFLICT DO NOTHING` inside one write transaction.

    Instances that open the same database file share it: `BEGIN IMMEDIATE` takes the
    write lock, so two processes can't both record the same nonce. `:memory:` is
    private to one instance."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            db_path, check_same_thread=False, isolation_level=None, timeout=10
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS nonces (key TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)"
        )

    def add(self, entries: Mapping[str, int], now: datetime) -> str | None:
        at = int(now.timestamp())
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DELETE FROM nonces WHERE expires_at <= ?", (at,))
                conflict = None
                for key, ttl in entries.items():
                    cursor = self._conn.execute(
                        "INSERT INTO nonces VALUES (?, ?) ON CONFLICT (key) DO NOTHING",
                        (key, at + ttl),
                    )
                    if cursor.rowcount == 0:
                        conflict = key
                        break
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("ROLLBACK" if conflict else "COMMIT")
        return conflict

    def seen(self, key: str, now: datetime) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM nonces WHERE key = ? AND expires_at > ?",
                (key, int(now.timestamp())),
            ).fetchone()
        return row is not None


# Runs inside Redis as one step: if any key exists, record nothing and return its
# position (1-based); otherwise set every key with its TTL and return 0.
ADD_ALL = """
for i, key in ipairs(KEYS) do
  if redis.call('EXISTS', key) == 1 then return i end
end
for i, key in ipairs(KEYS) do
  redis.call('SET', key, '1', 'EX', ARGV[i])
end
return 0
"""


class RedisNonceStore:
    """The optional shared backend: pass a `redis.Redis` client (`pip install
    agent-spend-guard[redis]`). A Lua script makes the multi-key add atomic. Expiry uses
    the Redis server's clock, so `now` is not used here. On Redis Cluster all keys of
    one `add` would need the same hash slot; this repo doesn't handle that."""

    def __init__(self, client: Any, prefix: str = "spend_guard:") -> None:
        self._redis = client
        self._prefix = prefix

    def add(self, entries: Mapping[str, int], now: datetime) -> str | None:
        keys = list(entries)
        position = self._redis.eval(
            ADD_ALL, len(keys), *[self._prefix + key for key in keys], *entries.values()
        )
        return keys[int(position) - 1] if position else None

    def seen(self, key: str, now: datetime) -> bool:
        return bool(self._redis.exists(self._prefix + key))
