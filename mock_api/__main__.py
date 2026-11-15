"""Run the mock: `python -m mock_api` (or `make mock`).

The organization key comes from MOCK_ORG_KEY, or from .mock/org_key, which is
created on first run (owner-only permissions, gitignored). Only a hint of the
key is ever printed. The signing key is made in memory at startup and never
written anywhere, so tokens from an earlier run stop verifying after a restart.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Mapping
from pathlib import Path

import uvicorn

from mock_api.app import BANNER, create_app
from mock_api.ids import key_hint, new_key
from mock_api.settings import Settings

ORG_KEY_FILE = Path(".mock/org_key")
ORG_KEY_FORMAT = re.compile(r"sk_sandbox_[0-9a-f]{32}")


def load_org_key(env: Mapping[str, str]) -> tuple[str, str]:
    """Return (key, where it came from)."""
    if env.get("MOCK_ORG_KEY"):
        key, source = env["MOCK_ORG_KEY"].strip(), "MOCK_ORG_KEY"
    elif ORG_KEY_FILE.exists():
        key, source = ORG_KEY_FILE.read_text().strip(), str(ORG_KEY_FILE)
    else:
        key, source = new_key("sk"), f"{ORG_KEY_FILE} (new)"
        ORG_KEY_FILE.parent.mkdir(exist_ok=True)
        ORG_KEY_FILE.touch(mode=0o600)
        ORG_KEY_FILE.write_text(key + "\n")
    if not ORG_KEY_FORMAT.fullmatch(key):
        raise SystemExit("the org key must be sk_sandbox_ followed by 32 hex characters")
    return key, source


def main() -> None:
    # One JSON line per request (req_ id, path, status) and per decision (dec_ id, verdict).
    logging.basicConfig(level=os.environ.get("MOCK_LOG_LEVEL", "INFO"), format="%(message)s")
    key, source = load_org_key(os.environ)
    settings = Settings.from_env(key)
    host = os.environ.get("MOCK_HOST", "127.0.0.1")
    port = int(os.environ.get("MOCK_PORT", "8787"))
    line = "=" * 64
    print(line)
    print(f"  {BANNER}")
    print("  It implements docs/SPEC.md on this machine. No real money moves.")
    print(f"  http://{host}:{port}   database: {settings.db_path}")
    print(f"  org key: {key_hint(key)}  (from {source})")
    print(line, flush=True)
    uvicorn.run(create_app(settings), host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
