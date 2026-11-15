"""Structured logs: one JSON object per line, carrying `dec_` and `req_` ids where known,
so one payment can be traced from the agent's request to the provider. Never log keys,
provider credentials or verdict tokens."""

from __future__ import annotations

import json
import logging
from typing import Any

log = logging.getLogger("spend_guard")


def log_event(event: str, **fields: Any) -> None:
    clean = {name: value for name, value in fields.items() if value is not None}
    log.info(json.dumps({"event": event, **clean}, default=str))
