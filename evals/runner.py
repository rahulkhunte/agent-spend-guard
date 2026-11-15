"""Run one policy through one scenario, and the whole matrix.

Each run gets a fresh in-process world (mock API, gate, provider, fake clock)
and a random generator seeded from `scenario:policy:run`, so the same command
always gives the same numbers.

Policies pay through `SpendTools.make_payment`, the same function the MCP
server and the OpenAI Agents tool register, so they see exactly what a model
would see.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from evals.oracle import unsafe_payments
from evals.policies import POLICIES, REPLAY, UNSAFE_INTENTS, Obedient, Purchase, Task
from evals.scenarios import SCENARIOS, Scenario
from mock_api.local import LocalWorld
from spend_guard.errors import VerificationError
from spend_guard.models import Order

DEFAULT_RUNS = 5


@dataclass(frozen=True)
class Call:
    intent: str
    order_id: str
    status: str  # what the tool answered; for a presented token, `accepted` or `rejected`
    paid: bool
    verdict: str | None = None  # the API's verdict, when there was one


@dataclass
class RunResult:
    scenario: str
    policy: str
    seed: str
    calls: list[Call] = field(default_factory=list)
    payments: int = 0  # every payment the provider recorded
    unsafe: list[str] = field(default_factory=list)  # from the oracle; must be empty
    decisions: int = 0  # how many decisions the API recorded in this run
    keys_per_order: int = 0  # the most Idempotency-Keys the gate used for any one order

    @property
    def attempts(self) -> int:
        """How many times the policy tried something it shouldn't have."""
        return sum(1 for call in self.calls if call.intent in UNSAFE_INTENTS)

    @property
    def stopped(self) -> int:
        """Of those, how many moved no money."""
        return sum(1 for call in self.calls if call.intent in UNSAFE_INTENTS and not call.paid)

    @property
    def paid_inside_mandate(self) -> int:
        """Of those, how many were paid. The oracle decides separately whether any
        payment was unsafe; these are payments the mandate itself allows."""
        return self.attempts - self.stopped


class Env:
    """What a policy can touch during one run. Implements `policies.AgentEnv`."""

    def __init__(self, world: LocalWorld, scenario: Scenario, rng: random.Random) -> None:
        self.world = world
        self.scenario = scenario
        self.rng = rng
        self.calls: list[Call] = []

    def pay(self, purchase: Purchase, intent: str = "task") -> dict[str, Any]:
        result = self.world.tools.make_payment(
            purchase.order_id, purchase.amount, purchase.currency,
            purchase.recipient, purchase.category, purchase.purpose,
        )  # fmt: skip
        self.calls.append(
            Call(intent, purchase.order_id, result["status"], result["paid"], result["verdict"])
        )
        self.world.clock.advance(seconds=1)  # an agent takes a moment between calls
        if (
            self.scenario.revoke_after_first_payment
            and result["paid"]
            and self.world.revoked_at is None
        ):
            self.world.revoke_mandate()  # the back office pulls the mandate mid-task
        return result

    def wait_until(self, moment: str) -> None:
        delay = datetime.fromisoformat(moment) - self.world.clock.now()
        if delay > timedelta(0):
            self.world.clock.advance(seconds=int(delay.total_seconds()) + 1)

    def wait(self, seconds: int) -> None:
        self.world.clock.advance(seconds=seconds)

    def present_again(self, purchase: Purchase) -> bool:
        """Present the verdict token this order was paid against a second time, the way
        a second settlement would. If the verifier accepted it, a second payment would
        be made here, and the oracle would report it."""
        tokens = [
            row["verdict_token"]
            for row in self.world.ledger.attempts(purchase.order_id)
            if row["status"] == "paid"
        ]
        if not tokens:
            return False
        order = Order(
            order_id=f"{purchase.order_id}-replayed", amount=purchase.amount,
            currency=purchase.currency, recipient=purchase.recipient,
            category=purchase.category,
        )  # fmt: skip
        try:
            self.world.verifier(tokens[-1], order)
        except VerificationError:
            self.calls.append(Call(REPLAY, order.order_id, "rejected", False))
            return False
        reference = self.world.ledger.attempts(purchase.order_id)[-1]["decision"]
        self.world.provider.pay(
            order_id=order.order_id, amount=order.amount, currency=order.currency,
            recipient=order.recipient, reference=reference,
        )  # fmt: skip
        self.calls.append(Call(REPLAY, order.order_id, "accepted", True))
        return True

    def choose(self, low: int, high: int) -> int:
        return self.rng.randint(low, high)

    def shuffled(self, items: tuple[str, ...]) -> list[str]:
        return self.rng.sample(items, len(items))


def approve_reviews(world: LocalWorld, env: Env, policy: Obedient, task: Task) -> None:
    """A person approves the review of each purchase in the task (not the extra ones a
    misbehaving policy created), and the integration pays the approval."""
    for purchase in task.purchases:
        pending = [
            row
            for row in world.ledger.attempts(purchase.order_id)
            if row["status"] == "pending_review"
        ]
        if not pending or world.ledger.is_claimed(purchase.order_id):
            continue
        approval = world.approve(pending[-1]["review"])
        order = Order(
            order_id=purchase.order_id, amount=purchase.amount, currency=purchase.currency,
            recipient=purchase.recipient, category=purchase.category,
        )  # fmt: skip
        if world.gate.pay_approved(order, approval).paid:
            policy.after_approval(env, purchase)


def run_one(scenario: Scenario, policy: Obedient, run: int) -> RunResult:
    seed = f"{scenario.id}:{policy.name}:{run}"
    rng = random.Random(seed)
    world = LocalWorld.build()
    task = scenario.build(rng)
    if scenario.setup is not None:
        scenario.setup(world, rng)
    env = Env(world, scenario, rng)
    policy.run(env, task)
    if scenario.human_approves:
        approve_reviews(world, env, policy, task)

    result = RunResult(scenario.id, policy.name, seed, env.calls)
    result.payments = len(world.provider.payments())
    result.unsafe = unsafe_payments(world, no_payment_is_safe=scenario.no_payment_is_safe)
    result.decisions = len(world.decision_log())
    keys: dict[str, set[int]] = {}
    for attempt in world.ledger.attempts():
        if attempt["attempt"] is not None:
            keys.setdefault(attempt["order_id"], set()).add(attempt["attempt"])
    result.keys_per_order = max((len(numbers) for numbers in keys.values()), default=0)
    return result


def run_all(runs: int = DEFAULT_RUNS) -> list[RunResult]:
    return [
        run_one(scenario, policy, run)
        for scenario in SCENARIOS
        for policy in POLICIES
        for run in range(1, runs + 1)
    ]
