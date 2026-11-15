"""Create one agent and one mandate on the running local mock, for the MCP server.

    uv run python -m mock_api            (in one terminal)
    uv run python scripts/seed_mock.py   (in another)

It talks to the local mock only. It reads the organization key from MOCK_ORG_KEY or
.mock/org_key, creates an agent and a mandate, and writes what the MCP server needs to
.mock/agent.env (owner-only, gitignored). The agent key is written to that file and
never printed. The organization key stays in the back office: it is not written there.
"""

from __future__ import annotations

import os
import secrets
import sys
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from spend_guard.client import DEFAULT_BASE_URL  # noqa: E402
from spend_guard.jsonutil import dumps, loads  # noqa: E402

MOCK_DIR = ROOT / ".mock"
ENV_FILE = MOCK_DIR / "agent.env"
RECIPIENTS = "vendor:acme_saas"


def org_key() -> str:
    key = os.environ.get("MOCK_ORG_KEY", "").strip()
    if not key and (MOCK_DIR / "org_key").is_file():
        key = (MOCK_DIR / "org_key").read_text().strip()
    if not key:
        raise SystemExit("no organization key: start the mock once (make mock) to create one")
    return key


def main() -> int:
    base_url = os.environ.get("SPEND_GUARD_BASE_URL", DEFAULT_BASE_URL)
    headers = {"Authorization": f"Bearer {org_key()}", "Content-Type": "application/json"}

    def post(path: str, body: dict[str, object]) -> dict[str, object]:
        try:
            response = httpx.post(f"{base_url}{path}", content=dumps(body), headers=headers)
        except httpx.HTTPError:
            raise SystemExit(f"the mock is not answering at {base_url}: run `make mock`") from None
        if response.status_code != 201:
            raise SystemExit(f"{path} answered {response.status_code}: {response.text[:200]}")
        result: dict[str, object] = loads(response.content)
        return result

    agent = post("/v1/agents", {"name": f"procurement-{secrets.token_hex(3)}"})
    mandate = post(
        "/v1/mandates",
        {
            "principal": "role:procurement_lead",
            "agent": agent["agent"],
            "limits": {
                "per_transaction": Decimal("500"),
                "per_month": Decimal("5000"),
                "currency": "USD",
            },
            "categories": ["saas"],
            "review_above": Decimal("250"),
            "expires": (date.today() + timedelta(days=90)).isoformat(),
        },
    )
    lines = [
        f"SPEND_GUARD_BASE_URL={base_url}",
        f"SPEND_GUARD_AGENT_KEY={agent['agent_key']}",
        f"SPEND_GUARD_MANDATES={mandate['mandate']}",
        f"SPEND_GUARD_ALLOWED_RECIPIENTS={RECIPIENTS}",
        f"SPEND_GUARD_LEDGER_DB={MOCK_DIR / 'ledger.db'}",
        f"SPEND_GUARD_PROVIDER_DB={MOCK_DIR / 'provider.db'}",
        f"SPEND_GUARD_NONCE_DB={MOCK_DIR / 'nonces.db'}",
    ]
    MOCK_DIR.mkdir(exist_ok=True)
    ENV_FILE.touch(mode=0o600)
    ENV_FILE.chmod(0o600)
    ENV_FILE.write_text("\n".join(lines) + "\n")
    print(f"agent {agent['agent']} and mandate {mandate['mandate']} created on {base_url}")
    print("mandate: 500 USD per transaction, 5,000 per 30 days, review above 250, category saas")
    print(f"approved payee: {RECIPIENTS}")
    print(f"settings for the MCP server written to {ENV_FILE} (the agent key is not shown)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
