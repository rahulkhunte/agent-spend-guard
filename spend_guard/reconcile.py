"""Reconcile the provider's payments against the decision log.

A payment that skipped the gate and has no matching decision shows up here: such a
bypass is visible, even though it isn't impossible. (A direct payment that quotes an
unused `allow` for the same amount, currency and recipient is not caught: the API did
authorize that spend.) This compares every provider payment with the
records from `GET /v1/exports/records` (org key) and lists each payment that is
not backed by exactly one matching `allow`:
- no decision reference at all (paid without asking)
- a reference that isn't in the export
- a decision whose verdict isn't `allow` (paid in observe mode, or a bypass)
- amount, currency or recipient different from what was authorized
- one `allow` backing more than one payment

    python -m spend_guard.reconcile --provider-db provider.db [--from 2026-10-01 --to 2026-11-01]

Reads the org key from SPEND_GUARD_ORG_KEY, or the mock's .mock/org_key file.
Exits 1 if anything is unmatched.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

from spend_guard.client import DEFAULT_BASE_URL, SpendGuardClient
from spend_guard.models import Decision
from spend_guard.provider import MockProvider, ProviderPayment

MOCK_ORG_KEY_FILE = Path(".mock/org_key")


@dataclass(frozen=True)
class Finding:
    payment: ProviderPayment
    problem: str


def reconcile(payments: Sequence[ProviderPayment], records: Sequence[Decision]) -> list[Finding]:
    """Every payment that is not backed by exactly one matching `allow` record."""
    by_id = {record.decision: record for record in records}
    uses = Counter(payment.reference for payment in payments if payment.reference)
    findings = []
    for payment in payments:
        ref = payment.reference
        record = by_id.get(ref) if ref else None
        if ref is None:
            problem = "no decision reference: paid without asking for a verdict"
        elif record is None:
            problem = f"decision {ref} is not in the exported decision log"
        elif record.verdict != "allow":
            problem = f"decision {ref} is {record.verdict}, not allow (mode {record.mode})"
        elif (record.request.amount, record.request.currency, record.request.recipient) != (
            payment.amount,
            payment.currency,
            payment.recipient,
        ):
            problem = f"payment differs from what decision {ref} authorized"
        elif uses[ref] > 1:
            problem = f"decision {ref} backs {uses[ref]} payments"
        else:
            continue
        findings.append(Finding(payment, problem))
    return findings


def _org_key() -> str:
    key = os.environ.get("SPEND_GUARD_ORG_KEY", "").strip()
    if not key and MOCK_ORG_KEY_FILE.exists():
        key = MOCK_ORG_KEY_FILE.read_text().strip()
    if not key:
        raise SystemExit("set SPEND_GUARD_ORG_KEY (or run the mock once to create .mock/org_key)")
    return key


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--provider-db", default="provider.db")
    parser.add_argument(
        "--base-url", default=os.environ.get("SPEND_GUARD_BASE_URL", DEFAULT_BASE_URL)
    )
    parser.add_argument("--from", dest="start", type=date.fromisoformat)
    parser.add_argument("--to", dest="end", type=date.fromisoformat)
    args = parser.parse_args(argv)

    payments = MockProvider(args.provider_db).payments()
    if not payments:
        print("no provider payments to reconcile")
        return 0
    # Default window: a day either side of the payments, `to` exclusive.
    start = args.start or min(p.paid_at.date() for p in payments) - timedelta(days=1)
    end = args.end or max(p.paid_at.date() for p in payments) + timedelta(days=1)
    records = SpendGuardClient(_org_key(), args.base_url).export_records(start, end)

    findings = reconcile(payments, records)
    print(f"{len(payments)} provider payments, {len(records)} decision records ({start} to {end})")
    for finding in findings:
        p = finding.payment
        print(f"  UNMATCHED {p.payment} order {p.order_id} {p.amount} {p.currency} "
              f"to {p.recipient}: {finding.problem}")  # fmt: skip
    if not findings:
        print("OK: every payment is backed by one matching allow")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
