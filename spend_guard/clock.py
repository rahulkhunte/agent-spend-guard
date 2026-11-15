"""One clock interface, shared by the mock, the gate and the verifier.

Every rule that depends on time (5-minute verdict expiry, 24-hour reviews and
idempotency, the 60-second velocity window, 25-hour webhook age) reads the
time from a Clock. Tests pass a FakeClock and move it forward instead of
sleeping.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime:
        """Current time, timezone-aware, in UTC."""
        ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class FakeClock:
    """A clock that only moves when a test moves it."""

    def __init__(self, start: datetime) -> None:
        if start.tzinfo is None:
            raise ValueError("FakeClock needs a timezone-aware start time")
        self._now = start.astimezone(UTC)

    def now(self) -> datetime:
        return self._now

    def advance(self, **delta: float) -> None:
        """Move forward, e.g. advance(seconds=61) or advance(days=30)."""
        self._now += timedelta(**delta)
