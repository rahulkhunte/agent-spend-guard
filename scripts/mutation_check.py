"""Mutation check: break one safety-critical line at a time and confirm a test notices.

    python scripts/mutation_check.py     (or `make mutation`)

A test that still passes when the code is wrong proves nothing. For each entry in
MUTATIONS this script copies the repo to a temporary folder, makes the one-line
change there, runs the named test, and expects it to FAIL. It exits 1 if any broken
version still passes. The working tree is never touched.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COPIED = ("spend_guard", "mock_api", "mcp_server", "integrations", "evals", "demo", "tests")
GATE = "tests/spend_guard/test_gate.py::"
VERIFY = "tests/spend_guard/test_verify.py::"

# (what is broken, file, the line as it is, the broken line, the test that must fail)
MUTATIONS = [
    (
        "the per-order lock is gone",
        "spend_guard/gate.py",
        "with self._order_lock(order.order_id):",
        "with threading.Lock():",
        GATE + "test_parallel_payments_for_one_order_pay_once",
    ),
    (
        "the recipient allowlist is skipped",
        "spend_guard/gate.py",
        "if order.recipient not in self.allowed_recipients:",
        "if False:",
        GATE + "test_recipient_not_on_allowlist_is_blocked",
    ),
    (
        "anything that isn't one known denial pays",
        "spend_guard/gate.py",
        'if decision.verdict == "allow":\n            # Verify and claim',
        'if decision.verdict != "deny_limit":\n            # Verify and claim',
        GATE + "test_unknown_verdict_is_denial",
    ),
    (
        "an unknown mode is treated as observe",
        "spend_guard/gate.py",
        'if decision.mode != "observe" or not settle:',
        'if decision.mode == "enforce" or not settle:',
        GATE + "test_unknown_mode_treated_as_enforce",
    ),
    (
        "every caller wins the claim on an order",
        "spend_guard/ledger.py",
        "return cursor.rowcount == 1",
        "return True",
        GATE + "test_parallel_observe_mode_payments_pay_once",
    ),
    (
        "an expired approval is accepted for another hour",
        "spend_guard/verify.py",
        'if now_ts >= claims["exp"]:',
        'if now_ts >= claims["exp"] + 3600:',
        VERIFY + "test_expired_at_exp_with_no_leeway",
    ),
    (
        "only verdicts starting with deny are rejected",
        "spend_guard/verify.py",
        'if claims["verdict"] != "allow":',
        'if claims["verdict"].startswith("deny"):',
        VERIFY + "test_anything_but_allow_rejected",
    ),
    (
        "the approval isn't compared with the order",
        "spend_guard/verify.py",
        'if not _matches_deal(claims["request"], deal):',
        "if False:",
        VERIFY + "test_claims_mismatch_rejected",
    ),
    (
        "a used nonce is accepted again",
        "spend_guard/verify.py",
        'if conflict is not None and conflict.startswith("nonce:"):',
        "if False:",
        VERIFY + "test_replay_rejected",
    ),
    (
        "the velocity rule never trips",
        "mock_api/engine.py",
        ">= VELOCITY_LIMIT:",
        ">= VELOCITY_LIMIT + 100:",
        "tests/mock_api/test_decision_codes.py::test_deny_velocity_on_11th_decision",
    ),
    (
        "the model-facing tools accept an organization key",
        "spend_guard/agent_tools.py",
        'if client.key_class != "agent":',
        "if False:",
        "tests/mcp_server/test_tools.py::test_only_an_agent_key_is_accepted",
    ),
    (
        "the tool guardrail lets a denial through",
        "integrations/openai_agents/tools.py",
        'if result.status is PaymentStatus.AUTHORIZED and result.verdict == "allow":',
        "if result.status is not PaymentStatus.PENDING_REVIEW:",
        "tests/integrations/test_openai_agents.py::test_guardrail_blocks_a_call_without_an_allow",
    ),
]


def run_test(folder: Path, test: str) -> bool:
    """True if the test passes in `folder`.

    `-B` (write no bytecode) matters. Python decides whether cached bytecode is stale from
    the source file's size and its modification time in whole seconds. A broken line of
    the same length, written within the same second as the original, would otherwise run
    the original's cached bytecode, and the broken version would look like it passed."""
    done = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", test],
        cwd=folder, capture_output=True, text=True, check=False,
    )  # fmt: skip
    return done.returncode == 0


def main() -> int:
    survivors = []
    with tempfile.TemporaryDirectory() as temp:
        copy = Path(temp) / "repo"
        copy.mkdir()
        for name in COPIED:
            shutil.copytree(ROOT / name, copy / name, ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copy(ROOT / "pyproject.toml", copy / "pyproject.toml")

        for what, file, old, new, test in MUTATIONS:
            path = copy / file
            original = path.read_text()
            if original.count(old) != 1:
                print(f"  SKIP  {what}: the line to break was not found exactly once in {file}")
                survivors.append(what)
                continue
            if not run_test(copy, test):
                print(f"  SKIP  {what}: {test} fails before any change")
                survivors.append(what)
                continue
            path.write_text(original.replace(old, new))
            caught = not run_test(copy, test)
            path.write_text(original)
            print(f"  {'caught' if caught else 'MISSED'}  {what}  ({test.split('::')[1]})")
            if not caught:
                survivors.append(what)

    print(f"{len(MUTATIONS) - len(survivors)} of {len(MUTATIONS)} broken versions were caught")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
