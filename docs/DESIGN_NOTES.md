# Design notes

The trade-offs behind the less obvious rules in [SPEC.md](SPEC.md), and the questions that are still open. Each note says what was chosen, what it costs, and which rule in [RULES.md](RULES.md) records it.

The common thread: where there was a choice, the repo takes the stricter option. A payment that is wrongly stopped can be retried. A payment that is wrongly made can't be taken back.

## 1. Decisions

### 1.1 Verdict first, then the recipient allowlist

- **The choice:** the gate asks the API for a verdict, and only then checks the recipient against its own allowlist. A recipient that isn't on the list is blocked, whatever the verdict and in either mode (R-165, R-179).
- **Why this order:** checking the list first would be cheaper, but the attempt would leave no trace in the decision log. Asking first means an attempt to pay an unlisted recipient, for example after a prompt injection, is on record on both sides: in the API's log, and in the gate's ledger with its `dec_` id.
- **What it costs:** the request is a real decision. It counts toward the agent's velocity. If it comes back `allow`, it also counts toward the mandate's rolling 30-day limit, even though nothing is paid.
- **Open question:** a deployment that sees many blocked recipients might prefer list-first, or a dry-run flag on the API so a blocked attempt is logged without using budget.

### 1.2 Idempotency keys are `order_id:attempt`

- **The choice:** the `Idempotency-Key` for an order is `<order_id>:<attempt>`, starting at attempt 1 (R-167).
- **Why:** a plain `order_id` key makes every denial permanent for 24 hours, including `deny_velocity`, which is about timing and not about the order. A random key per call does the opposite: a retry after a timeout could create a second decision. The attempt number sits between the two. Retries inside an attempt share a key, so they replay one decision. Only the gate can move to the next attempt, and only in one case (1.3).
- **What it costs:** the gate has to remember the last attempt for each order. It reads that from its own ledger.
- **A consequence worth knowing:** the same order id with a different amount is `409 idempotency_conflict`, so the gate fails closed. Changing an order means a new order id.

### 1.3 The velocity backoff

- **The choice:** after a `deny_velocity`, the gate keeps the order's key until 60 seconds after it **first** saw that denial. Then the next call uses attempt + 1 and gets a fresh decision. The result carries `retry_at` (R-180).
- **Why 60 seconds:** the velocity rule looks at one 60-second window. After one full window, the decisions that caused the denial have aged out.
- **Why "first saw":** counting from the latest call would let an impatient agent push its own retry time back forever. Asking early just replays the denial and changes nothing.
- **What it costs:** an order can wait longer than strictly needed, because the window may have cleared sooner.

### 1.4 A lost race reports `already_paid`

- **The choice:** when several calls race to pay one order, exactly one pays. The others report `already_paid`, not a replay error (R-172, R-181).
- **Why:** concurrent calls for one order share one decision, and so one nonce. Without care, a loser reaches the verifier just after the winner recorded the nonce and is told "replay", which reads like an attack when the order is simply being paid.
- **How:** the gate verifies and claims under a per-order lock (64 locks, picked by a hash of the order id, so memory stays bounded). Across processes, which don't share locks, a replay on an order that is now claimed is also reported as `already_paid`. A replay on an order nobody claimed is still blocked.
- **What it costs:** calls for different orders that hash to the same lock wait for each other briefly.

### 1.5 The day a mandate expires

- **The choice:** a mandate is expired from 00:00 UTC on its `expires` date (R-030).
- **Why:** "expires on 1 December" can be read as "works through 1 December" or "stops when 1 December starts", and in any time zone. The earlier, UTC reading is the stricter one, and one fixed time zone keeps every party's answer the same.
- **What it costs:** an operator west of UTC loses part of the last local day.

### 1.6 Velocity counts decisions, not requests

- **The choice:** the 10-per-60-seconds rule counts decisions. A request rejected with a 4xx and an idempotent replay make no decision, so they don't count. A review approval is a decision and does count (R-026, R-027).
- **Why:** counting replays would punish the client for retrying safely, which is the behaviour the idempotency rules exist to encourage.
- **What it costs:** a client could send many invalid requests without tripping velocity. The per-key rate limit covers that.

### 1.7 Observe mode relaxes only the verdict

- **The choice:** in observe mode the gate pays whatever the verdict and records `would_have_blocked`. Its own checks still apply: the allowlist, token verification on an `allow`, and failing closed (R-163, R-175).
- **Why:** observe mode exists to measure what the policy would stop before turning it on. It is not a switch that turns off the integration's own safety. Also, `mode` isn't in the signed token, so a response whose token fails verification gives no trustworthy mode either.
- **What it costs:** in observe mode a verdict other than `allow` is paid without any token check, because the verifier accepts only an `allow`. That payment rests on two unsigned response fields, `mode` and `verdict`. Whoever can alter the API's responses could turn enforce into observe. Observe mode is for measuring a policy before turning it on, with a person watching.
- **Related:** a `mode` the gate doesn't recognize is treated as `enforce` (R-174).

### 1.8 A failed provider call is not retried

- **The choice:** if the provider call raises, the order stays claimed and the result is `provider_error`. Nothing retries it automatically (R-177).
- **Why:** after a failed call, money may or may not have moved. Paying twice is worse than paying late, so a person checks the provider's records.
- **What it costs:** an order can be stuck until someone looks.

### 1.9 The nonce is recorded last, and all-or-nothing

- **The choice:** the verifier records the nonce only after every other check has passed. For an approval, the nonce and the `supersedes` marker are written in one atomic step (R-209, R-210).
- **Why:** a token that fails a fixable check (say, an allowlisted mandate that wasn't configured yet) must still be usable once the problem is fixed. And two separate writes would leave a window where one is recorded and the other isn't.

### 1.10 Webhooks: store after the re-read, act after storing

- **The choice:** the receiver re-reads the object, then stores the event, then acts (R-227, R-229).
- **Why:** a failed re-read answers `503` with nothing stored, so the sender's retry is processed later. Storing before acting means two racing deliveries can't both act, because only one insert of the `jti` succeeds.
- **What it costs:** if the action itself crashed after the event was stored, that event wouldn't be retried. That includes a notification that fails to send: the review would reach nobody until someone looks at the stored events. The actions here are a notification and a hand-off. The payment is protected again by the gate's claim and the verifier's nonce.

### 1.11 Smaller choices

- **Byte-for-byte idempotency (R-077):** "the same body" means identical bytes. Two bodies that differ only in whitespace are different requests, and get `409`.
- **Body over 64 KB is `400` (R-090):** the API uses seven error codes, and `413` isn't one of them.
- **A taken agent name is `400` (R-046):** `409` is kept for idempotency conflicts only.
- **16 KB token limit (R-190):** far larger than a token with ordinary field sizes. The spec doesn't bound the length of an amount, so a verdict with an absurdly long one could exceed the limit. It would be rejected, which fails closed.
- **An `Idempotency-Key` is tied to its endpoint (R-078):** without that, a key used to disable an agent would replay "disabled" as the answer to a later enable call.
- **An order id is printable ASCII (R-183):** it becomes part of the `Idempotency-Key` header, and a header can't carry anything else.
- **`supersedes` remembered for 25 hours (R-213):** a review lives 24 hours and its approval 5 minutes.
- **Events dated in the future are rejected (R-226):** otherwise a forward-dated event would never fail the 25-hour age check.
- **Every amount is a `Decimal`:** from 2^33 upward, two amounts one millionth apart can become the same binary float (`8589934592.000001` and `8589934592.000002` do). Using decimals at every size removes the question.
- **Key-set redirects are refused (R-199):** the keys are fetched with httpx and `follow_redirects=False`, so this doesn't depend on which PyJWT version is installed.

## 2. Open questions

- **Splitting and relabelling get through.** The evals show it ([EVALS.md](../EVALS.md), finding 2): an amount cut into pieces under the review threshold is paid piece by piece, and a purchase relabelled with an allowed category is paid. Each such payment is inside the mandate, so neither the API nor the gate can call it wrong. Today the bounds are the rolling 30-day limit, the velocity rule and the recipient allowlist. Options: a per-recipient daily cap in the mandate, a review trigger on several near-threshold payments to one recipient, or categories set by the payee's record instead of by the agent.
- **Should the API offer a dry run?** `check_spend` in the MCP server is a real authorization: it makes a decision, counts toward velocity, and on `allow` uses rolling 30-day budget. A dry-run flag would avoid that, at the price of a second code path in the policy engine.
- **Should recipients be part of a mandate?** Today the allowlist lives in the integration. Putting it in the mandate would put it under the same signature and audit trail, but every new vendor would need a new mandate.
- **Should `mode` be signed?** It would let a verifier trust it. It is left out so that flipping the switch never invalidates tokens already issued.
- **How should a `provider_error` order be released?** Today a person decides. A real provider's idempotency key could make an automatic retry safe.
- **Should reconcile read the gate's ledger too?** Today it compares the provider's payments with the decision log only. A direct payment that quotes an unused `allow` for the same amount, currency and recipient passes, and `check_spend` produces such allows. A ledger comparison (every provider payment must match a `paid` row) would catch it.
- **The outage eval is narrower than the tests.** In the evals (E7) the API answers `5xx` to every call. Client timeouts and a refused connection are covered by unit tests, not by an eval run.
- **A failed review notification.** The receiver stores an event before acting on it, so a notification that fails is not retried (1.10). A real deployment would queue notifications and retry them.
- **Redis Cluster:** recording a nonce and a `supersedes` marker together uses two keys, which a cluster would need in the same hash slot.
