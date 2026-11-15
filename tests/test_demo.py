"""The narrated demo runs to the end and its story holds."""

from __future__ import annotations

import pytest

import demo.__main__ as demo


def test_demo_runs_and_its_story_holds(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`make demo` exits 0: two payments went through the gate, a reused approval was
    already_paid, and reconcile flagged exactly the one payment that skipped the gate."""
    monkeypatch.setattr(demo, "PAUSE", 0)
    assert demo.main() == 0
    printed = capsys.readouterr().out
    for phrase in (
        "status: paid",
        "verdict: deny_limit",
        "status: pending_review",
        "HUMAN ACTION NEEDED",
        "gate.pay_approved(order-3) → status: paid",
        "second time → status: already_paid",
        "verdict: deny_revoked",
        "status: no_verdict",
        "UNMATCHED off-the-books",
        "2 payments, 460.00 USD",
    ):
        assert phrase in printed, phrase
    assert "sk_sandbox_" not in printed and "ak_sandbox_" not in printed and "eyJ" not in printed
