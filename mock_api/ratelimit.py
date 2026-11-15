"""Per-key sliding 60-second window, reported in RateLimit-* headers."""

from __future__ import annotations

import math
from collections import defaultdict, deque

from spend_guard.clock import Clock

WINDOW_SECONDS = 60


class SlidingWindow:
    def __init__(self, limit: int, clock: Clock) -> None:
        self.limit = limit
        self.clock = clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def hit(self, key: str) -> tuple[bool, dict[str, str]]:
        """Count one request for `key`. Returns (allowed, RateLimit-* headers)."""
        now = self.clock.now().timestamp()
        hits = self._hits[key]
        while hits and hits[0] <= now - WINDOW_SECONDS:
            hits.popleft()
        allowed = len(hits) < self.limit
        if allowed:
            hits.append(now)
        reset = math.ceil(hits[0] + WINDOW_SECONDS - now) if hits else 0
        headers = {
            "RateLimit-Limit": str(self.limit),
            "RateLimit-Remaining": str(self.limit - len(hits)),
            "RateLimit-Reset": str(reset),
        }
        return allowed, headers
