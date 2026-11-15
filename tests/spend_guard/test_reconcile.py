"""Reconciling provider payments against the exported decision log."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from pathlib import Path

import pytest

from spend_guard import reconcile as reconcile_module
from spend_guard.client import SpendGuardClient
from spend_guard.models import Decision
from spend_guard.provider import MockProvider
from spend_guard.reconcile import reconcile
from tests.spend_guard.conftest import ORG_KEY, VENDOR, World


def export(world: World) -> list[Decision]:
    org = SpendGuardClient(ORG_KEY, http=world.mock.client)
    today = world.mock.clock.now().date()
    return org.export_records(today, today + timedelta(days=1))


def test_reconcile_clean_when_every_payment_has_an_allow(world: World) -> None:
    """R-173: payments made through the gate all match an allow record"""
    for n in range(3):
        assert world.gate.pay(world.order(f"o-{n}")).paid
    assert reconcile(world.provider.payments(), export(world)) == []


def test_reconcile_flags_bypass_payment(world: World) -> None:
    """R-173: a payment made without asking for a verdict is listed"""
    world.gate.pay(world.order("o-1"))
    world.provider.pay(
        order_id="o-bypass", amount=Decimal("900"), currency="USD",
        recipient="vendor:new", reference=None,
    )  # fmt: skip
    [finding] = reconcile(world.provider.payments(), export(world))
    assert finding.payment.order_id == "o-bypass" and "without asking" in finding.problem


def test_reconcile_flags_observe_mode_payment_on_deny(world: World) -> None:
    """R-173: a payment backed by a denial (observe mode) is listed with its verdict"""
    world.mock.post("/v1/enforcement", {"mode": "observe"})
    world.gate.pay(world.order("o-1", "720.00"))
    [finding] = reconcile(world.provider.payments(), export(world))
    assert "deny_limit, not allow (mode observe)" in finding.problem


def test_reconcile_flags_mismatch_reuse_and_unknown_reference(world: World) -> None:
    """R-173: wrong amount, one allow reused, and a reference missing from the log are listed"""
    paid = world.gate.pay(world.order("o-1"))
    pay = world.provider.pay
    pay(order_id="o-2", amount=Decimal("120.01"), currency="USD", recipient=VENDOR,
        reference=paid.decision)  # fmt: skip
    pay(order_id="o-3", amount=Decimal("1"), currency="USD", recipient=VENDOR,
        reference="dec_not_ours")  # fmt: skip
    problems = [f.problem for f in reconcile(world.provider.payments(), export(world))]
    assert problems == [
        f"decision {paid.decision} backs 2 payments",
        f"payment differs from what decision {paid.decision} authorized",
        "decision dec_not_ours is not in the exported decision log",
    ]


def test_reconcile_command(
    world: World,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """R-173: `python -m spend_guard.reconcile` prints unmatched payments and exits 1"""
    db = str(tmp_path / "provider.db")
    MockProvider(db, clock=world.mock.clock).pay(
        order_id="o-bypass", amount=Decimal("5"), currency="USD", recipient=VENDOR,
        reference=None,
    )  # fmt: skip
    monkeypatch.setenv("SPEND_GUARD_ORG_KEY", ORG_KEY)
    monkeypatch.setattr(
        reconcile_module,
        "SpendGuardClient",
        lambda key, base_url: SpendGuardClient(key, http=world.mock.client),
    )
    assert reconcile_module.main(["--provider-db", db]) == 1
    output = capsys.readouterr().out
    assert "UNMATCHED" in output and "o-bypass" in output and ORG_KEY not in output
