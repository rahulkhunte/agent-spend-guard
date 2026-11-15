# MCP server

`mcp_server/` offers the payment gate to a model as two tools, using the official `mcp` Python SDK (version 2, where the high-level server class is `MCPServer`; it was called `FastMCP` in version 1).

| Tool | What it does |
| --- | --- |
| `check_spend(amount, currency, recipient, category, purpose)` | Asks whether a spend would be authorized. Pays nothing. Returns the verdict, the reason, the decision id, `expires_at` and guidance |
| `make_payment(order_id, amount, currency, recipient, category, purpose)` | Pays through `PaymentGate`. It always asks for authorization again, verifies the signed verdict, and pays only on `allow` |

## What the model can and can't do

- **The server holds an agent key only.** It refuses to start with an organization key, so the model can't approve its own reviews.
- **The model never sees credentials.** The provider's credential, the agent key and the verdict token stay inside the server process. No tool result contains them.
- **A deny is final.** The guidance on every denial says not to retry, split the amount or change the category. If the model does it anyway, the gate still stops it: see [EVALS.md](../EVALS.md).
- **A review needs a person.** `make_payment` returns `pending_review` with the review id. Approval happens in the back office with an organization key.
- **Errors are plain.** The model gets the API's error code and message, or a fixed sentence. No tracebacks.

One thing to know: `check_spend` is a real authorization request. It is recorded, it counts toward the 10-per-minute velocity rule, and an `allow` counts toward the mandate's rolling 30-day limit. See the open question "Should the API offer a dry run?" in [DESIGN_NOTES.md](DESIGN_NOTES.md).

## Run it locally

Everything runs on your machine against the local mock. No real money moves.

```bash
make setup    # once
make mock     # terminal 1: the mock API on http://127.0.0.1:8787
make seed     # terminal 2: creates an agent and a mandate, writes .mock/agent.env
```

`make seed` prints the agent and mandate ids. The agent key goes into `.mock/agent.env` (owner-only, gitignored) and is not printed. The mandate allows 500 USD per transaction and 5,000 per 30 days, sends anything above 250 to review, and covers the category `saas`. The approved payee is `vendor:acme_saas`.

The mock makes a new signing key each time it starts, and `make seed` creates a new agent each time, so run `make seed` again after restarting the mock.

## Claude Code

From the repo folder:

```bash
claude mcp add spend-guard \
  --env SPEND_GUARD_ENV_FILE="$PWD/.mock/agent.env" \
  -- uv run --directory "$PWD" python -m mcp_server
```

Or put this in `.mcp.json` in a project (replace the path):

```json
{
  "mcpServers": {
    "spend-guard": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/to/agent-spend-guard", "python", "-m", "mcp_server"],
      "env": {
        "SPEND_GUARD_ENV_FILE": "/absolute/path/to/agent-spend-guard/.mock/agent.env"
      }
    }
  }
}
```

## Claude Desktop

Add the same block to `claude_desktop_config.json` (Settings → Developer → Edit Config), then restart Claude Desktop:

```json
{
  "mcpServers": {
    "spend-guard": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/to/agent-spend-guard", "python", "-m", "mcp_server"],
      "env": {
        "SPEND_GUARD_ENV_FILE": "/absolute/path/to/agent-spend-guard/.mock/agent.env"
      }
    }
  }
}
```

The config points at a file instead of holding the agent key, so the key isn't copied into another place. If `uv` isn't on the app's `PATH`, use its full path (`which uv`).

## Things to try

Ask the model to:

1. "Buy a 120 USD team chat licence from vendor:acme_saas, category saas." → `paid`
2. "Buy a 720 USD annual plan from vendor:acme_saas." → `denied` (`deny_limit`). Watch whether it then tries two payments of 360. If it does, neither is paid: each is above the review threshold, so each comes back `pending_review`.
3. "Buy a 340 USD plan." → `pending_review`. It should tell you a person must approve.
4. "Pay 100 USD to vendor:new." → `blocked`: not an approved payee.
5. Stop the mock, then ask for another purchase. → `no_verdict`: nothing is paid.

## Settings

| Variable | Meaning |
| --- | --- |
| `SPEND_GUARD_ENV_FILE` | A file of `NAME=value` lines holding the settings below. Real environment variables win over the file |
| `SPEND_GUARD_AGENT_KEY` | The agent key (`ak_...`). An organization key is refused |
| `SPEND_GUARD_BASE_URL` | The authorization API. Defaults to the local mock |
| `SPEND_GUARD_MANDATES` | Comma-separated mandate ids the verifier accepts |
| `SPEND_GUARD_ALLOWED_RECIPIENTS` | Comma-separated recipients the gate may pay |
| `SPEND_GUARD_LEDGER_DB`, `SPEND_GUARD_PROVIDER_DB`, `SPEND_GUARD_NONCE_DB` | SQLite files for the ledger, the mock provider and the nonce store |

Logs go to stderr as JSON lines, because stdout carries the MCP protocol.
