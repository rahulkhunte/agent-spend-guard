"""Mock configuration, read from environment variables.

Fault injection exists to test fail-closed behaviour: it makes the mock slow,
broken or rate-limited on purpose. Faults apply only to
`POST /v1/authorizations`, the call a payment gate depends on, and can also be
changed at runtime through `POST /_mock/faults`.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass
class Faults:
    latency_ms: int = 0  # added to every authorization request
    error_rate: float = 0.0  # share answered with 500 server_error
    timeout_rate: float = 0.0  # share that hang for timeout_seconds, then answer 503
    timeout_seconds: float = 30.0
    rate_limit_burst: int = 0  # the next N authorization requests get 429
    retry_after_seconds: int = 1  # Retry-After sent with a burst 429
    # Every decision gets this verdict instead of the real one, e.g. "deny_future_rule":
    # a decision code the client has never seen, still signed. Empty means off.
    forced_verdict: str = ""


@dataclass
class Settings:
    org_key: str
    db_path: str = "mock.db"
    rate_limit: int = 600  # requests per key per sliding 60 s
    webhook_interval: float = 1.0  # seconds between delivery passes; 0 turns the loop off
    fault_seed: int | None = None  # makes random faults repeatable
    faults: Faults = field(default_factory=Faults)

    @classmethod
    def from_env(cls, org_key: str, env: Mapping[str, str] = os.environ) -> Settings:
        seed = env.get("MOCK_FAULT_SEED")
        faults = Faults(
            latency_ms=int(env.get("MOCK_LATENCY_MS", "0")),
            error_rate=float(env.get("MOCK_ERROR_RATE", "0")),
            timeout_rate=float(env.get("MOCK_TIMEOUT_RATE", "0")),
            timeout_seconds=float(env.get("MOCK_TIMEOUT_SECONDS", "30")),
            rate_limit_burst=int(env.get("MOCK_429_BURST", "0")),
            retry_after_seconds=int(env.get("MOCK_RETRY_AFTER", "1")),
            forced_verdict=env.get("MOCK_FORCED_VERDICT", ""),
        )
        return cls(
            org_key=org_key,
            db_path=env.get("MOCK_DB_PATH", "mock.db"),
            rate_limit=int(env.get("MOCK_RATE_LIMIT", "600")),
            webhook_interval=float(env.get("MOCK_WEBHOOK_INTERVAL", "1")),
            fault_seed=int(seed) if seed else None,
            faults=faults,
        )
