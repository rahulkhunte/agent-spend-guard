"""A mock payment provider. It holds the payment credentials; nothing else does.

The threat model: an agent that holds the credentials itself can pay without
asking. So the credentials live inside this object, which only the gate holds.
The agent, the MCP server's model and the logs never see them: they are made at
runtime (or read from the environment), never printed, and kept out of `repr`.

`pay` is deliberately unguarded, like a real provider API: anyone holding this
object can pay. That is the point of the demo: the safety comes from who holds
it, and `reconcile` makes a payment that skipped the gate visible.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Protocol

from spend_guard.clock import Clock, SystemClock
from spend_guard.jsonutil import decimal_text

APPEND_ONLY = """
CREATE TABLE IF NOT EXISTS payments (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, payment TEXT UNIQUE NOT NULL, order_id TEXT NOT NULL,
    amount TEXT NOT NULL, currency TEXT NOT NULL, recipient TEXT NOT NULL, reference TEXT,
    paid_at INTEGER NOT NULL);
CREATE TRIGGER IF NOT EXISTS payments_no_update BEFORE UPDATE ON payments
    BEGIN SELECT RAISE(ABORT, 'payments is append-only'); END;
CREATE TRIGGER IF NOT EXISTS payments_no_delete BEFORE DELETE ON payments
    BEGIN SELECT RAISE(ABORT, 'payments is append-only'); END;
"""


@dataclass(frozen=True)
class ProviderPayment:
    payment: str
    order_id: str
    amount: Decimal
    currency: str
    recipient: str
    reference: str | None  # the dec_ id the payer quoted, if any
    paid_at: datetime


class PaymentProvider(Protocol):
    def pay(
        self, *, order_id: str, amount: Decimal, currency: str, recipient: str,
        reference: str | None,
    ) -> ProviderPayment: ...  # fmt: skip

    def payments(self) -> list[ProviderPayment]: ...


class MockProvider:
    """Records payments in its own append-only SQLite table. No money moves."""

    def __init__(self, db_path: str = ":memory:", *, clock: Clock | None = None) -> None:
        # A stand-in secret, so there is something real to keep away from the agent.
        self.__secret = os.environ.get("MOCK_PROVIDER_SECRET") or secrets.token_hex(32)
        self.clock = clock or SystemClock()
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self._conn.executescript(APPEND_ONLY)

    def __repr__(self) -> str:
        return "MockProvider(credentials hidden)"

    def pay(
        self, *, order_id: str, amount: Decimal, currency: str, recipient: str,
        reference: str | None,
    ) -> ProviderPayment:  # fmt: skip
        now = self.clock.now()
        # The "credential" signs the payment id, the way a real call would be authenticated.
        nonce = secrets.token_hex(8)
        digest = hmac.new(self.__secret.encode(), nonce.encode(), hashlib.sha256).hexdigest()
        payment = ProviderPayment(
            payment=f"pay_{digest[:16]}",
            order_id=order_id,
            amount=amount,
            currency=currency,
            recipient=recipient,
            reference=reference,
            paid_at=now,
        )
        with self._lock:
            self._conn.execute(
                "INSERT INTO payments (payment, order_id, amount, currency, recipient, reference, "
                "paid_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    payment.payment, order_id, decimal_text(amount), currency, recipient,
                    reference, int(now.timestamp()),
                ),
            )  # fmt: skip
        return payment

    def payments(self) -> list[ProviderPayment]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT payment, order_id, amount, currency, recipient, reference, paid_at "
                "FROM payments ORDER BY seq"
            ).fetchall()
        return [
            ProviderPayment(
                payment=row[0], order_id=row[1], amount=Decimal(row[2]), currency=row[3],
                recipient=row[4], reference=row[5], paid_at=datetime.fromtimestamp(row[6], UTC),
            )
            for row in rows
        ]  # fmt: skip
