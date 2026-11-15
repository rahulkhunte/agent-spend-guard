"""The mock policy engine: evaluates spend requests and manages the objects they depend on.

Callers hold the app lock around every method, so each method sees and writes
a consistent state. Methods raise ApiError for anything the API answers with
an error status.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

from mock_api.errors import ApiError
from mock_api.ids import key_hash, new_id, new_key
from mock_api.models import AgentCreate, AuthorizationRequest, MandateCreate, WebhookCreate
from mock_api.signing import ISSUER, Signer
from mock_api.store import Store, iso, ts
from mock_api.webhooks import Webhooks
from spend_guard.clock import Clock
from spend_guard.jsonutil import decimal_text, to_decimal

VERDICT_TTL = 300  # every verdict: exp = iat + 300
REVIEW_TTL = 24 * 3600
VELOCITY_WINDOW = 60
VELOCITY_LIMIT = 10  # the 11th decision inside the window is deny_velocity
MONTH_WINDOW = 30 * 24 * 3600


@dataclass(frozen=True)
class Outcome:
    verdict: str
    reason: str
    mandate: dict[str, Any] | None = None  # the mandate evaluated against; None on deny_no_mandate


def money(value: Decimal) -> str:
    """Amounts in reasons show two decimals: 720 -> "720.00"."""
    exponent = value.as_tuple().exponent
    if isinstance(exponent, int) and exponent >= -2:
        return f"{value:.2f}"
    return decimal_text(value)


class Engine:
    def __init__(self, store: Store, signer: Signer, clock: Clock, webhooks: Webhooks) -> None:
        self.store = store
        self.signer = signer
        self.clock = clock
        self.webhooks = webhooks
        # A label per organization, from its creation date. It never changes with mandates.
        self.policy_version = f"pol_{store.org_created_on()}.1"

    def _now(self) -> int:
        return ts(self.clock.now())

    # Authorizations

    def authorize(
        self, agent: str, request: AuthorizationRequest, *, forced_verdict: str = ""
    ) -> dict[str, Any]:
        now = self._now()
        outcome = self._evaluate(agent, request, now)
        if forced_verdict:  # mock fault: a verdict the client may never have seen
            reason = f"mock fault: verdict forced to {forced_verdict}"
            outcome = Outcome(forced_verdict, reason, outcome.mandate)
        review = None
        if outcome.verdict == "review":
            assert outcome.mandate is not None
            review = {
                "review": new_id("rev_"),
                "waits_for": outcome.mandate["principal"],
                "expires_at": iso(now + REVIEW_TTL),
                "status": "pending",
            }
        echo = {
            "agent": agent,
            "amount": request.amount,
            "currency": request.currency,
            "recipient": request.recipient,
            "category": request.category,
        }
        decision = self._issue(
            echo,
            outcome.verdict,
            outcome.reason,
            outcome.mandate["mandate"] if outcome.mandate else None,
            now,
            review=review,
            metadata=request.metadata,
        )
        with self.store.transaction():
            self.store.add_decision(decision, now)
            if review is not None:
                self.store.add_review(
                    review["review"],
                    decision["decision"],
                    review["waits_for"],
                    now,
                    now + REVIEW_TTL,
                )
                self.webhooks.emit("decision.review_pending", decision)
        return decision

    def _evaluate(self, agent: str, request: AuthorizationRequest, now: int) -> Outcome:
        if self.store.agent_status(agent) != "active":
            return Outcome("deny_no_mandate", f"agent {agent} is disabled")
        mandates = self.store.mandates_for(agent, request.currency)
        if not mandates:
            return Outcome(
                "deny_no_mandate", f"no mandate for {agent} in currency {request.currency}"
            )
        # Oldest first: the first allow wins, then the first review, else the oldest result.
        results = [self._check_mandate(mandate, agent, request, now) for mandate in mandates]
        for wanted in ("allow", "review"):
            for result in results:
                if result.verdict == wanted:
                    return result
        return results[0]

    def _check_mandate(
        self, mandate: dict[str, Any], agent: str, request: AuthorizationRequest, now: int
    ) -> Outcome:
        """The gate order from SPEC section 6.1. The first gate that fails decides."""
        mandate_id = mandate["mandate"]
        limits = mandate["limits"]
        amount = request.amount

        if self.store.revoked_at(mandate_id) is not None:
            return Outcome("deny_revoked", f"mandate {mandate_id} was revoked", mandate)
        if self._is_expired(mandate, now):
            return Outcome(
                "deny_expired", f"mandate {mandate_id} expired on {mandate['expires']}", mandate
            )
        if request.category not in mandate["categories"]:
            return Outcome(
                "deny_category",
                f"category {request.category} is not allowed by mandate {mandate_id}",
                mandate,
            )
        per_transaction = to_decimal(limits["per_transaction"])
        if amount > per_transaction:
            return Outcome(
                "deny_limit",
                f"amount {money(amount)} exceeds per_transaction limit {money(per_transaction)}",
                mandate,
            )
        if "per_month" in limits:
            per_month = to_decimal(limits["per_month"])
            used = self.store.allowed_total(mandate_id, since=now - MONTH_WINDOW)
            if used + amount > per_month:
                return Outcome(
                    "deny_limit",
                    f"amount {money(amount)} would exceed per_month limit {money(per_month)} "
                    "over the last 30 days",
                    mandate,
                )
        if self.store.decision_count(agent, since=now - VELOCITY_WINDOW) >= VELOCITY_LIMIT:
            return Outcome(
                "deny_velocity",
                f"agent {agent} already had {VELOCITY_LIMIT} decisions in the last 60 seconds",
                mandate,
            )
        if "review_above" in mandate:
            review_above = to_decimal(mandate["review_above"])
            if amount > review_above:
                return Outcome(
                    "review",
                    f"amount {money(amount)} is above review_above {money(review_above)}",
                    mandate,
                )
        return Outcome("allow", f"within mandate {mandate_id}", mandate)

    @staticmethod
    def _is_expired(mandate: dict[str, Any], now: int) -> bool:
        # R-030: expired from 00:00 UTC on the expires date, the stricter choice.
        today = datetime.fromtimestamp(now, UTC).date()
        return today >= date.fromisoformat(mandate["expires"])

    def _issue(
        self,
        echo: dict[str, Any],
        verdict: str,
        reason: str,
        mandate_id: str | None,
        now: int,
        *,
        supersedes: str | None = None,
        review: dict[str, Any] | None = None,
        metadata: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Build a signed decision. The caller stores it."""
        decision_id = new_id("dec_")
        nonce = new_id("n_")
        decision: dict[str, Any] = {
            "decision": decision_id,
            "request": echo,
            "verdict": verdict,
            "reason": reason,
        }
        if mandate_id is not None:
            decision["mandate"] = mandate_id
        decision["policy_version"] = self.policy_version
        decision["nonce"] = nonce
        decision["mode"] = self.store.mode()[0]  # recorded per decision; the API blocks nothing
        decision["issued_at"] = iso(now)
        if verdict == "allow":
            decision["expires_at"] = iso(now + VERDICT_TTL)
        if supersedes is not None:
            decision["supersedes"] = supersedes
        claims = self._verdict_claims(
            decision_id, echo, verdict, mandate_id, nonce, now, supersedes
        )
        decision["verdict_token"] = self.signer.sign(claims)
        if review is not None:
            decision["review"] = review
        if metadata:
            decision["metadata"] = metadata
        return decision

    def _verdict_claims(
        self,
        decision_id: str,
        echo: dict[str, Any],
        verdict: str,
        mandate_id: str | None,
        nonce: str,
        now: int,
        supersedes: str | None,
    ) -> dict[str, Any]:
        """What the token signs. Not reason, mode, metadata or review. No aud."""
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "jti": decision_id,
            "iat": now,
            "exp": now + VERDICT_TTL,
            "verdict": verdict,
        }
        if mandate_id is not None:
            claims["mandate"] = mandate_id
        claims["policy_version"] = self.policy_version
        claims["nonce"] = nonce
        claims["request"] = echo
        if supersedes is not None:
            claims["supersedes"] = supersedes
        return claims

    # Reviews

    def review_status(self, review: Any, now: int) -> str:
        outcome = self.store.review_outcome(review["review"])
        if outcome is not None:
            return outcome
        return "expired" if now >= review["expires_at"] else "pending"

    @staticmethod
    def review_view(review: Any, status: str) -> dict[str, Any]:
        return {
            "review": review["review"],
            "waits_for": review["waits_for"],
            "expires_at": iso(review["expires_at"]),
            "status": status,
        }

    def _open_review(self, review_id: str, now: int) -> Any:
        self.expire_reviews()
        review = self.store.review(review_id)
        if review is None:
            raise ApiError(404, f"no review {review_id}")
        status = self.review_status(review, now)
        if status != "pending":
            raise ApiError(400, f"review {review_id} is {status}, not pending")
        return review

    def approve_review(self, review_id: str) -> dict[str, Any]:
        """A new allow decision with `supersedes`. The original review decision is untouched."""
        now = self._now()
        review = self._open_review(review_id, now)
        original = self.store.decision(review["decision"])
        assert original is not None
        echo = original["request"]
        agent = echo["agent"]
        mandate = self.store.mandate(original["mandate"])
        assert mandate is not None
        mandate_id = mandate["mandate"]

        # Re-checks before approving. Any failure: 400, nothing issued, review stays pending.
        if self.store.agent_status(agent) != "active":
            raise ApiError(400, f"agent {agent} is disabled")
        if self.store.revoked_at(mandate_id) is not None:
            raise ApiError(400, f"mandate {mandate_id} was revoked")
        if self._is_expired(mandate, now):
            raise ApiError(400, f"mandate {mandate_id} expired on {mandate['expires']}")
        if "per_month" in mandate["limits"]:
            per_month = to_decimal(mandate["limits"]["per_month"])
            used = self.store.allowed_total(mandate_id, since=now - MONTH_WINDOW)
            if used + to_decimal(echo["amount"]) > per_month:
                raise ApiError(
                    400,
                    f"approving would exceed per_month limit {money(per_month)} for {mandate_id}",
                )

        decision = self._issue(
            echo,
            "allow",
            f"review {review_id} approved",
            mandate_id,
            now,
            supersedes=original["decision"],
            metadata=original.get("metadata"),  # R-059: the approval keeps the order reference
        )
        with self.store.transaction():
            self.store.add_decision(decision, now)
            self.store.add_review_outcome(review_id, "approved", decision["decision"], now)
            self.webhooks.emit("decision.resolved", decision)
        return decision

    def deny_review(self, review_id: str) -> dict[str, Any]:
        """Closes the review in place. No decision is issued."""
        now = self._now()
        review = self._open_review(review_id, now)
        view = self.review_view(review, "denied")
        with self.store.transaction():
            self.store.add_review_outcome(review_id, "denied", None, now)
            self.webhooks.emit("decision.resolved", view)
        return view

    def expire_reviews(self) -> None:
        """Close every pending review that is 24 hours old. Called before review actions and on
        each webhook pass."""
        now = self._now()
        for review in self.store.reviews_due_to_expire(now):
            with self.store.transaction():
                self.store.add_review_outcome(review["review"], "expired", None, now)
                self.webhooks.emit("decision.resolved", self.review_view(review, "expired"))

    # Agents

    def create_agent(self, body: AgentCreate) -> dict[str, Any]:
        agent_id = f"agt_{body.name}"
        if self.store.agent(agent_id) is not None:
            raise ApiError(400, f"agent name {body.name} is already taken")
        now = self._now()
        record: dict[str, Any] = {"agent": agent_id, "name": body.name, "created_at": iso(now)}
        if body.metadata:
            record["metadata"] = body.metadata
        agent_key = new_key("ak")
        with self.store.transaction():
            self.store.add_agent(agent_id, record, now)
            self.store.add_agent_status(agent_id, "active", now)
            self.store.add_key(key_hash(agent_key), "agent", agent_id, now)
        # The only time the key is ever returned. Only its hash is stored.
        return {**self.agent_view(agent_id), "agent_key": agent_key}

    def agent_view(self, agent_id: str) -> dict[str, Any]:
        record = self.store.agent(agent_id)
        if record is None:
            raise ApiError(404, f"no agent {agent_id}")
        view = {
            "agent": agent_id,
            "name": record["name"],
            "status": self.store.agent_status(agent_id),
            "created_at": record["created_at"],
        }
        if "metadata" in record:
            view["metadata"] = record["metadata"]
        return view

    def set_agent_status(self, agent_id: str, status: str) -> dict[str, Any]:
        self.agent_view(agent_id)  # 404 if unknown
        if self.store.agent_status(agent_id) != status:
            self.store.add_agent_status(agent_id, status, self._now())
        return self.agent_view(agent_id)

    # Mandates

    def create_mandate(self, body: MandateCreate) -> dict[str, Any]:
        if self.store.agent(body.agent) is None:
            raise ApiError(400, f"unknown agent {body.agent}")
        now = self._now()
        record = {"mandate": new_id("mnd_"), **body.model_dump(exclude_none=True)}
        record["expires"] = body.expires.isoformat()
        record["created_at"] = iso(now)
        self.store.add_mandate(record, now)
        return self.mandate_view(record)

    def mandate_view(self, record: dict[str, Any]) -> dict[str, Any]:
        revoked_at = self.store.revoked_at(record["mandate"])
        view = dict(record)
        if revoked_at is not None:
            view["status"] = "revoked"
            view["revoked_at"] = iso(revoked_at)
        elif self._is_expired(record, self._now()):
            view["status"] = "expired"
        else:
            view["status"] = "active"
        return view

    def get_mandate(self, mandate_id: str) -> dict[str, Any]:
        record = self.store.mandate(mandate_id)
        if record is None:
            raise ApiError(404, f"no mandate {mandate_id}")
        return self.mandate_view(record)

    def revoke_mandate(self, mandate_id: str) -> dict[str, Any]:
        record = self.store.mandate(mandate_id)
        if record is None:
            raise ApiError(404, f"no mandate {mandate_id}")
        if self.store.revoked_at(mandate_id) is not None:
            raise ApiError(400, f"mandate {mandate_id} is already revoked")
        with self.store.transaction():
            self.store.add_revocation(mandate_id, self._now())
            view = self.mandate_view(record)
            self.webhooks.emit("mandate.revoked", view)
        return view

    # Enforcement and webhooks

    def enforcement_view(self) -> dict[str, str]:
        mode, since = self.store.mode()
        return {"mode": mode, "since": iso(since)}

    def set_mode(self, mode: str) -> dict[str, str]:
        if self.store.mode()[0] != mode:
            self.store.add_mode(mode, self._now())  # the change itself is a record
        return self.enforcement_view()

    def create_webhook(self, body: WebhookCreate) -> dict[str, Any]:
        now = self._now()
        record = {
            "webhook": new_id("whk_"),
            "url": body.url,
            "events": list(body.events),
            "status": "active",
            "created_at": iso(now),
        }
        self.store.add_webhook(record, now)
        return record
