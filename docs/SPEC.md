# Spec: an agent-spend authorization API

This is the reference spec for agent-spend-guard. It describes a small authorization API that answers one question, "may this agent spend this?", and signs the answer. It also describes what the code around that API (the integration) must do, because the API blocks nothing by itself.

The repo implements this spec twice: `mock_api/` is a local reference mock of the API, and `spend_guard/` is the integration side (client, payment gate, verifier, webhook receiver). Every numbered rule in [RULES.md](RULES.md) links to a section here. The reasoning behind the less obvious choices is in [DESIGN_NOTES.md](DESIGN_NOTES.md).

There is no hosted service. The base URL in every example is the local mock, `http://127.0.0.1:8787`.

## 1. Terms

- **Agent:** a program (usually driven by an LLM) that wants to spend money.
- **Organization:** whoever owns the agents and the money.
- **Mandate:** a written grant from the organization to one agent: how much, in which currency, for which categories, until when.
- **Decision:** the API's recorded answer to one spend request. Its **verdict** is one of 8 decision codes.
- **Verdict token:** the decision, signed as a JWT, so a third party can check it.
- **Review:** a decision that waits for a person.
- **Integration:** the code that holds the payment credentials and calls the API before paying. In this repo, `PaymentGate`.

## 2. Authentication

Every request carries `Authorization: Bearer <key>`. There are two classes of key:

| Class | Prefix | Held by | May call |
| --- | --- | --- | --- |
| Agent key | `ak_sandbox_`, `ak_live_` | one agent's runtime | create an authorization; read its own decisions |
| Organization key | `sk_sandbox_`, `sk_live_` | the back office | everything |

- A key is the prefix plus 32 hex characters. The API stores only a hash of it.
- A missing or unknown key is `401 unauthorized`, on any path, including paths that don't exist. The one exception is the public key set (section 15.1), which is read without a key.
- An agent key on an organization-only endpoint is `403 forbidden`.
- An object that belongs to another agent is reported as `404 not_found`, not `403`, so an id is never confirmed to a stranger.
- An organization key must never reach an agent.

## 3. Endpoints

All paths are under `/v1`. "Org" means an organization key.

| Method and path | Key | Success | Returns |
| --- | --- | --- | --- |
| `POST /agents` | Org | `201` | The agent, with its `agent_key` shown once |
| `POST /agents/{id}/disable` | Org | `200` | The agent, `status: disabled` |
| `POST /agents/{id}/enable` | Org | `200` | The agent, `status: active` |
| `POST /mandates` | Org | `201` | The mandate |
| `GET /mandates/{id}` | Org | `200` | The mandate |
| `POST /mandates/{id}/revoke` | Org | `200` | The mandate, `status: revoked` |
| `POST /authorizations` | Agent, or Org naming `agent` | `201` | A decision, whatever the verdict |
| `GET /decisions/{id}` | Org (all), Agent (own) | `200` | A decision |
| `POST /reviews/{id}/approve` | Org | `201` | A new `allow` decision with `supersedes` |
| `POST /reviews/{id}/deny` | Org | `200` | The review, closed |
| `GET /enforcement` | Org | `200` | `{mode, since}` |
| `POST /enforcement` | Org | `200` | `{mode, since}` |
| `POST /webhooks` | Org | `201` | The webhook endpoint |
| `GET /exports/records?from=&to=` | Org | `200` | NDJSON, one decision per line |
| `GET /.well-known/jwks.json` (not under `/v1`) | none | `200` | The public key set |

Reviews have no read endpoint: `GET /reviews` and `GET /reviews/{id}` are `404`. A review's state reaches the integration through the authorization response, the approve or deny response, and webhooks.

## 4. Authorization request

`POST /v1/authorizations` with a JSON body:

| Field | Type | Required | Rule |
| --- | --- | --- | --- |
| `amount` | number | yes | A positive JSON number in major units (`340` with `USD` is 340 dollars). A string, a boolean, zero or a negative number is `400` |
| `currency` | string | yes | At most 128 characters. Compared exactly and case-sensitively with the mandate's `limits.currency`. Nothing is converted |
| `recipient` | string | yes | At most 1,024 characters. Signed into the verdict, but not checked against any list |
| `category` | string | yes | At most 128 characters. Checked against the mandate's `categories` |
| `protocol` | string | no | One of `x402`, `mpp`, `acp`, `ap2`, `card`; anything else is `400`. Informational only |
| `agent` | string | with an org key | Which agent the request is for. Required on an organization key, ignored on an agent key |
| `metadata` | object | no | At most 20 keys, string values of at most 500 characters. Returned on the decision unread |

- A missing field or a field the request doesn't define is `400 invalid_request`.
- Amounts are exact decimals from end to end. An implementation must never pass an amount through a binary float. On the integration side an order's amount is a decimal, a string or an integer; a float is refused.

### 4.1 Transport limits

- A body over 64 KB is refused with `400 invalid_request` before it is parsed.
- The `Idempotency-Key` header is optional and at most 255 characters.

## 5. Decision object

Every evaluated request returns HTTP `201` and a decision, **including denials**. A denial is a normal answer, not an error.

```json
{
  "decision": "dec_41c9e07a",
  "request": { "agent": "agt_buyer", "amount": 120.00, "currency": "USD",
               "recipient": "vendor:acme_saas", "category": "saas" },
  "verdict": "allow",
  "reason": "within mandate mnd_2b7f90d1",
  "mandate": "mnd_2b7f90d1",
  "policy_version": "pol_2026-10-27.1",
  "nonce": "n_6a0de3b2",
  "mode": "enforce",
  "issued_at": "2026-10-27T12:00:00Z",
  "expires_at": "2026-10-27T12:05:00Z",
  "verdict_token": "eyJhbGciOiJFUzI1NiIs..."
}
```

| Field | Present | Meaning |
| --- | --- | --- |
| `decision` | always | The `dec_` id. Also the token's `jti` |
| `request` | always | Echo of `agent`, `amount`, `currency`, `recipient`, `category` |
| `verdict` | always | One of the 8 codes in section 6 |
| `reason` | always | Which rule decided, in words. For people; never parse it, and pass it on unchanged |
| `mandate` | not on `deny_no_mandate` | The mandate the request was evaluated against |
| `policy_version` | always | A `pol_` label derived from the organization's creation date |
| `nonce` | always | An `n_` single-use marker |
| `mode` | always | `observe` or `enforce` at the time of the decision |
| `issued_at` | always | When it was decided. Also the token's `iat` |
| `expires_at` | `allow` only | `issued_at` plus 5 minutes |
| `verdict_token` | always | The signed form (section 15) |
| `supersedes` | review approvals only | The `review` decision this one resolves |
| `review` | `review` only | The review object (section 9) |
| `metadata` | if sent | Echo of the request's metadata |

A decision is written to the log before the response is returned.

## 6. Decision codes

| Code | When |
| --- | --- |
| `allow` | Every check passed, or a person approved a review |
| `review` | The amount is above the mandate's `review_above` |
| `deny_limit` | Over `per_transaction`, or over the rolling 30-day `per_month` |
| `deny_velocity` | The agent already had 10 decisions in the last 60 seconds |
| `deny_category` | The category isn't on the mandate's list |
| `deny_expired` | The mandate has expired |
| `deny_revoked` | The mandate was revoked |
| `deny_no_mandate` | The agent is disabled, or has no mandate in the request's currency |

Limits are strict at the boundary: an amount equal to `per_transaction` or `review_above` passes that check; one cent more does not.

### 6.1 Evaluation order

For one mandate, the checks run in this order, and the first one that fails decides:

1. an applicable mandate exists (else `deny_no_mandate`)
2. not revoked (else `deny_revoked`)
3. not expired (else `deny_expired`)
4. category listed (else `deny_category`)
5. within `per_transaction` (else `deny_limit`)
6. within the rolling 30-day `per_month` (else `deny_limit`)
7. velocity (else `deny_velocity`)
8. at or below `review_above` (else `review`)

Passing all of them is `allow`.

### 6.2 Several mandates

An agent may hold several mandates in one currency. All of them take part, including revoked and expired ones, oldest first. The verdict is the first `allow`; otherwise the first `review`; otherwise the result for the oldest mandate.

### 6.3 Velocity

- The rule is fixed: 10 decisions per agent per 60 seconds, so the 11th is `deny_velocity`. It is not per mandate and not configurable.
- It counts **decisions**. A request rejected with a 4xx, or an idempotent replay, makes no decision and does not count. A review approval is a decision for that agent and does count.

### 6.4 Unknown codes

New codes may be added later. Anything that reads a verdict must treat a code it doesn't recognize as a denial. The only string that ever pays is exactly `allow`.

## 7. Mandates

`POST /v1/mandates` body:

| Field | Required | Rule |
| --- | --- | --- |
| `principal` | yes | Who grants it, for example `role:procurement_lead` |
| `agent` | yes | The agent it applies to. An unknown agent is `400` |
| `limits.per_transaction` | yes | The cap for one spend |
| `limits.per_month` | no | The cap for a rolling 30 days: every `allow` under this mandate in the last 30 days, plus this request |
| `limits.currency` | yes | At most 128 characters |
| `categories` | yes | Allowed categories, each at most 128 characters |
| `review_above` | no | Above this amount, the verdict is `review` |
| `expires` | yes | A date, written exactly `YYYY-MM-DD`. Any other spelling is `400` |
| `escrow.required_above` | no | Stored and returned. Never changes a verdict |

- The response is the same shape plus the `mnd_` id in `mandate` and `status: "active"`.
- **Mandates are never edited.** To change limits, revoke the mandate and create a new one.
- **Mandates do not restrict recipients.** They limit amounts and categories. Who may be paid is the integration's job (section 19.4).

### 7.1 Revocation

- `POST /v1/mandates/{id}/revoke` returns the mandate with `status: "revoked"` and `revoked_at`.
- The agent's next request under it is `deny_revoked`. Reviews pending under it can no longer be approved.
- An `allow` issued before the revocation stays valid until it expires. So an order authorized just before a revocation can still be paid for up to five minutes after it.
- Revoking a mandate twice is `400`.

### 7.2 Expiry

A mandate is expired from 00:00 UTC on its `expires` date. So a mandate with `expires: 2026-12-01` works through 30 November and is denied from the first second of 1 December, UTC.

## 8. Agents

- `name` is a lowercase slug. The id is `agt_` plus the name. A name already taken is `400`.
- `agent_key` appears once, in the create response, and can't be read again.
- Disabling an agent makes its mandates stop matching: its next request is `deny_no_mandate`, and its pending reviews can't be approved. `/enable` reverses it.

## 9. Reviews and approvals

A `review` verdict carries a review object:

```json
{ "review": "rev_90ab31c4", "waits_for": "role:procurement_lead",
  "expires_at": "2026-10-28T12:00:00Z", "status": "pending" }
```

`status` is one of `pending`, `approved`, `denied`, `expired`.

- A review expires 24 hours after it is created.
- Approve and deny need an organization key.
- **Approval issues a new decision:** an `allow` with a new nonce, its own 5-minute expiry, and `supersedes` set to the original review decision. It copies the original request's `metadata`. The original decision stays in the log untouched.
- **Approval re-checks first:** the agent is active, the mandate isn't revoked or expired, and the amount still fits in `per_month`. If any check fails, the call returns `400 invalid_request` with the reason, no decision is issued, and the review stays pending.
- A review yields at most one `allow`. Acting on a review that is no longer pending is `400`.
- Deny returns the review, closed, with `200`. Denial and expiry issue no decision.
- A new review fires `decision.review_pending`; its resolution fires `decision.resolved` (section 17).

What the integration must do with a review:

- Pay nothing while it is pending. Return the review id and its expiry to the caller.
- After approval, pay only the new `allow` whose `supersedes` is the review decision recorded for that same order.

## 10. Observe and enforce

- `POST /v1/enforcement {"mode": "observe" | "enforce"}` sets one switch for the whole environment. It needs an organization key and accepts no other value. `GET /v1/enforcement` returns the current `mode` and `since`.
- A change applies from the next decision. Every decision records the mode it was made under.
- The sandbox environment, which the mock behaves like, starts in `enforce`.
- **The API blocks nothing in either mode.** It answers and records. Stopping a payment is the integration's job.

What the integration must do:

- Read `mode` from each decision, so a switch takes effect on the next payment with no deploy.
- **Enforce:** pay only when the verdict is exactly `allow`.
- **Observe:** pay whatever the verdict, and record that enforce would have blocked it.
- Treat a mode it doesn't recognize as `enforce`.
- Observe mode relaxes only the verdict. The integration's own checks apply in both modes: the recipient allowlist, verification of the token on an `allow`, and failing closed when there is no verdict.
- In observe mode a verdict other than `allow` is paid without its token being verified, because the verifier accepts only an `allow`. That payment rests on the response's `mode` and `verdict` fields, which are not signed (section 15). Observe mode is for measuring a policy, not for running unattended.

## 11. Idempotency

Every `POST` accepts an `Idempotency-Key` header.

- The same API key, the same `Idempotency-Key` and the same request within 24 hours returns the original result, with the header `Idempotency-Replayed: true`. "The same request" means the same method and path, and a byte-for-byte identical body.
- The same `Idempotency-Key` with a different body, or on a different endpoint, is `409 idempotency_conflict`. A key never replays one call's result as the answer to another.
- The same `Idempotency-Key` sent with a different API key is a new request.
- **Never stored:** `401`, `403`, `429`, any `5xx`, and requests refused before they reach the endpoint (a body over 64 KB, an invalid `Content-Length`, a key over 255 characters). So a retry after a `5xx` is evaluated fresh.
- **Stored and replayed for 24 hours:** every other result, including other `4xx` errors. A corrected body needs a new key.

## 12. Errors

```json
{ "error": { "code": "invalid_request", "message": "limits.currency is required", "request_id": "req_5d1c20e9" } }
```

| HTTP | Code | When |
| --- | --- | --- |
| 400 | `invalid_request` | Malformed body, missing or unknown field, or an action the object's state no longer allows |
| 401 | `unauthorized` | Missing or unknown key |
| 403 | `forbidden` | Valid key of the wrong class |
| 404 | `not_found` | No such object, or not yours |
| 409 | `idempotency_conflict` | Same `Idempotency-Key`, different body or endpoint |
| 429 | `rate_limited` | Over the key's rate limit |
| 5xx | `server_error` | The API failed. Safe to retry with the same `Idempotency-Key` |

- Every response, success or error, carries an `X-Request-Id` header with a `req_` id. It is the join key for tracing a call that never produced a decision.
- An unsupported method on a known path is `400`, not `405`.
- A body that can't be parsed, however it is malformed, is `400`. An unexpected failure inside the API is `500 server_error` in the same envelope, and the message says nothing about the cause.

## 13. Rate limits

- Limits apply per key over a sliding 60-second window.
- Every authenticated response carries `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset` (seconds). Unauthenticated responses carry none.
- A `429` adds `Retry-After`, in seconds.

## 14. Object ids

Every object id has a prefix: `agt_` (agent), `mnd_` (mandate), `dec_` (decision), `rev_` (review), `pol_` (policy version), `n_` (nonce), `whk_` (webhook endpoint), `evt_` (event), `req_` (request).

## 15. Verdict token

The verdict token is an ES256 JWT.

- **Header:** `alg: ES256`, `typ: JWT`, and a `kid`. Sandbox keys have a `kid` starting `sandbox-`.
- **Claims:**

| Claim | Value |
| --- | --- |
| `iss` | `https://verdicts.agent-spend-guard.local` |
| `jti` | The decision id |
| `iat` | Issue time. Equal to the decision's `issued_at` |
| `exp` | `iat + 300`, on every verdict, denials included |
| `verdict` | The decision code |
| `mandate` | The mandate id (absent on `deny_no_mandate`) |
| `policy_version` | As on the decision |
| `nonce` | As on the decision |
| `request` | `agent`, `amount`, `currency`, `recipient`, `category` |
| `supersedes` | On a review approval only |

- `request.amount` is written as an exact JSON number.
- **Not signed:** `reason`, `mode`, `metadata` and `review` are not in the token. There is no `aud` claim.

### 15.1 Key set

The public keys are served as a JWK Set at `/.well-known/jwks.json`, with `Cache-Control: max-age=300` and `Access-Control-Allow-Origin: *`. Webhook events are signed with the same keys.

## 16. Verifying a verdict

Before money moves on an `allow`, the integration verifies the token against the order it is about to pay. The checks run in this order, and each rejection names the check that failed:

| Step | Check |
| --- | --- |
| 1 | **Format:** at most 16 KB; exactly three base64url segments with no padding and no whitespace |
| 2 | **Key and signature:** the key is found by `kid`; ES256 only; `iss` is the expected issuer |
| 3 | **Required claims:** `exp`, `iat`, `iss`, `nonce`, `verdict` and `request` are present with the right types |
| 4 | **Environment:** a `sandbox-` kid is rejected unless sandbox is explicitly allowed |
| 5 | **Clock:** `iat` more than 60 seconds in the future is rejected |
| 6 | **Approval:** `verdict` is exactly `allow`. Every other value, known or not, is rejected |
| 7 | **Expiry:** rejected from `exp` onward, with no leeway |
| 8 | **Order match:** the signed amount equals the order's as a decimal value; currency matches case-sensitively; recipient matches exactly |
| 9 | **Mandate:** the token names a mandate, and it is one the operator listed |
| 10 | **Audience:** a token carrying `aud` is rejected unless it names this integration |
| 11 | **Replay:** the nonce has not been accepted before; for an approval, neither has its `supersedes` |

A webhook event must never pass as a verdict. Events have no `exp` and no `nonce`, so step 3 rejects them.

### 16.1 Key lookup

- The key set is cached for five minutes.
- An unknown `kid`: fetch the set once more, then reject. After that, no refetch for 30 seconds, so unknown kids can't be used to hammer the key endpoint.
- A `kid` that appears twice in the set is rejected.
- Redirects are not followed when fetching keys. If the set can't be fetched, nothing verifies and nothing is paid.

### 16.2 Amounts

The payload is parsed with decimals after the signature check. Amounts are compared as decimal values: `340` equals `340.00`, and `8589934592.000001` does not equal `8589934592.000002` (as binary floats they would be the same number).

### 16.3 Nonce store

- The nonce is recorded last, and only when every other check has passed. A token that fails a check never uses up its nonce.
- Recording is atomic: set-if-absent in one step. For an approval, the nonce and the `supersedes` marker are recorded together, all or nothing.
- A nonce is kept for at least 600 seconds, and at least until `exp` plus 60 seconds. An accepted `supersedes` is remembered for 25 hours, which outlasts any approval that could still be presented (a review lives 24 hours, an approval 5 minutes).
- The store can be shared by every verifier instance that might see the same token (one SQLite file, or Redis).

## 17. Webhooks

`POST /v1/webhooks {url, events[]}` registers an HTTPS endpoint for a list of event types.

### 17.1 Delivery

- An event is an HTTP `POST` with `Content-Type: application/jwt`. The body is an ES256 JWT signed with the verdict keys.
- Claims: `iss`, `jti` (an `evt_` id), `iat`, `type`, `data`. **No `exp` and no `nonce`.**
- Only subscribed event types are delivered.
- A `2xx` acknowledges. Anything else is retried with the identical token, so the `jti` stays the same. Retry delays double from 1 second up to 1 hour, and stop 24 hours after the event was created.

### 17.2 Event types

| Type | When | `data` |
| --- | --- | --- |
| `decision.review_pending` | A verdict came back `review` | The review decision |
| `decision.resolved` | A review was approved, denied or expired | Approval: the new `allow` decision. Denial or expiry: the review object |
| `mandate.revoked` | A mandate was revoked | The mandate |
| `ping` | A test | Nothing to act on |

`mandate.expiring` and `escrow.*` are accepted as subscription names but never sent by the mock.

### 17.3 Receiving

A receiver must:

1. Accept only `Content-Type: application/jwt`.
2. Verify the signature and issuer as for a verdict, without requiring `exp`. Require `type` and `data`, so a verdict token is not an event.
3. Reject a `sandbox-` kid on a production endpoint.
4. Reject an event older than 25 hours, or dated more than 60 seconds in the future.
5. Deduplicate on `jti`.
6. Before acting, re-read the object with its own key, and act on what the API returns, not on the event's copy. A `404` means the object isn't ours: acknowledge and ignore.
7. For a denied or expired review (which can't be re-read), act only if its `rev_` id came from one of its own authorization responses.
8. Answer `2xx` to acknowledge. If the re-read fails because the API is down, answer `503` and record nothing, so the retry is processed.
9. Keep every received event, with its raw token, append-only.
10. Make sure `decision.review_pending` reaches a person.

## 18. Reading decisions and exports

- `GET /v1/decisions/{id}`: an organization key reads any decision; an agent key reads its own.
- `GET /v1/exports/records?from=&to=` streams NDJSON, one decision per line, with its `verdict_token`. `from` and `to` are dates; `from` is inclusive and `to` is exclusive.
- Records are append-only. Nothing is edited or deleted; a change is a new record.
- Review denials and expiries are not decisions, so the exported review decision keeps `"status": "pending"`.
- Two exports of the same window are byte-identical.

## 19. Integration requirements

The API only answers. These are the rules for the code that pays.

### 19.1 Client

- Retry only when there was no answer (a timeout, a refused connection or any other transport failure) or on a `5xx`, and always with the same `Idempotency-Key` and body. Never retry any other error.
- When every attempt ends without an answer, raise one error type for "no answer". A transport failure never escapes as the HTTP library's own exception.
- On `429`, wait `Retry-After` seconds, then retry. If the wait is longer than the caller allows, raise instead of blocking.
- Read the `RateLimit-*` headers on every response. When none remain, wait for the reset before the next call, up to the longest wait the caller allows; after that the call is sent, and a `429` is handled as above.
- Every error carries the response's `X-Request-Id`.
- A denial is returned as a decision, never raised as an error.
- Ignore response fields it doesn't know.
- Send amounts as exact decimals.

### 19.2 Fail closed

No verdict, no payment. An error, a timeout or an outage is not an `allow`, and that includes an API that can't be reached at all. Each of these is reported as `no_verdict` and written to the ledger; none is raised to the caller. There is no fail-open setting.

### 19.3 Credentials behind the gate

- The payment credentials live in the code that runs the check. The agent, and the model driving it, never hold them.
- Each agent key lives only in that agent's runtime. An organization key never reaches an agent.
- Credentials, keys and verdict tokens appear in no result, `repr` or log line.

### 19.4 Recipient allowlist

Mandates don't restrict recipients, so the integration keeps its own list of who may be paid. It asks for the verdict first, then blocks a recipient that isn't on the list, whatever the verdict and in either mode, and records the block with its `dec_` id.

### 19.5 Idempotency keys per order

- The `Idempotency-Key` for an order is `<order_id>:<attempt>`. Retries within an attempt reuse it, so they get the same decision.
- The attempt number goes up only after a `deny_velocity`, and only once 60 seconds have passed since the integration first saw that denial. Asking earlier replays the denial and doesn't move the time.
- Every other denial is final for that order: asking again replays it, for the 24 hours the API remembers the key (section 11).
- An order id is printable ASCII with no spaces, at most 200 characters, because it becomes part of a header.

### 19.6 Pay at most once

- An order is paid at most once, even under concurrent calls. The integration claims the order atomically before calling the provider.
- A call that loses the race for an order reports `already_paid`, never a replay error.
- If the provider call fails, the order stays claimed and is not retried automatically. Money may or may not have moved, so a person checks.

### 19.7 Ledger

The integration keeps its own append-only record of every payment attempt: the order id, the `dec_` id, the `req_` id (including when there was no decision), and the raw verdict token of what it paid against.

### 19.8 Reconciliation

Compare the provider's payments with the exported decision log. Every provider payment should be backed by exactly one `allow` with the same amount, currency and recipient. Anything else is listed, so a payment that bypassed the check and has no matching `allow` is visible, even though it isn't impossible.

What this does not catch: a payment made directly at the provider that quotes an unused `allow` for the same amount, currency and recipient. The API did authorize that spend, but the gate never verified the token or recorded the attempt. Comparing the provider's payments with the integration's own ledger as well would show it (see the design notes).

### 19.9 Tools exposed to a model

When the integration is offered to a model as tools (an MCP server, or function tools in an agent framework):

- The tool process holds an agent key only. It refuses to start with an organization key.
- A payment tool always goes through the gate: it asks for a fresh authorization, verifies the token, and pays only on `allow`. A separate "check" tool pays nothing.
- A result carries the verdict, the API's `reason` unchanged, ids, and one line of guidance. It never carries a key, a provider credential, a verdict token or signing material.
- The guidance for a denial says it is final for that request: no retry, no splitting the amount, no relabelling the category. The guidance for a review says a person must approve.
- An error carries the API's own error code and message, or a fixed sentence when the API didn't answer. This holds for the check tool and the payment tool alike. It never carries a traceback or the integration's internal detail.
- A tool takes the amount as a string. A JSON number is refused before anything is sent, or read as an exact decimal, so it never passes through a binary float.
- A verdict the tool doesn't recognize is presented as a denial.
- A guardrail in front of a payment tool may ask for the order's verdict first, without paying. It uses the same `Idempotency-Key` as the payment, so the two share one decision. It lets the tool run only on `allow`, in either mode.
- A review stops the agent's run and hands the decision to a person. The model can't approve its own review, because approval needs an organization key.

## 20. Mock-only behaviour

The mock in `mock_api/` differs from this spec in three deliberate ways:

- It accepts `http://localhost` and `http://127.0.0.1` webhook URLs, so the demo needs no TLS.
- It signs with a key made at startup, under a `sandbox-mock-<date>` kid.
- It has fault injection under `/_mock/` (added latency, a `5xx` rate, timeouts, a `429` burst, a forced verdict), used to test failing closed. Nothing under `/_mock/` is part of the API.

Not implemented: escrow, usage reports, list endpoints and pagination, key rotation, webhook list/get/delete/ping calls, and `mandate.expiring` events.

## 21. Related work

The design follows common patterns in agent-payment protocols: a signed mandate that states what an agent may spend, and a signed, short-lived approval that the paying side verifies before settling. AP2 and x402 are two public examples of those patterns. This spec doesn't implement either of them.

The `protocol` field (section 4) is informational and names the payment protocol an agent is using. Besides the two above:

- **MPP (Machine Payments Protocol):** an open protocol that lets an agent pay for a service per request, over HTTP.
- **ACP (Agentic Commerce Protocol):** an open protocol that lets an agent complete a checkout with a merchant on a person's behalf.

Neither is implemented here, and the mock never reads the field.
