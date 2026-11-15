"""Check that the numbers in README.md are the repo's real numbers.

    python scripts/check_readme.py

It fails if:
- the eval summary table in README.md differs from the one in EVALS.md
- the test count in README.md differs from what pytest collects
- the rule count in README.md differs from the rows in docs/RULES.md
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def summary_rows(text: str) -> list[list[str]]:
    """The policy rows of the eval summary table, as cells, without the date-free header."""
    rows = []
    for line in text.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) == 7 and cells[1].isdigit():
            rows.append(cells)
    return rows


def main() -> int:
    readme = (ROOT / "README.md").read_text()
    problems = []

    evals_text = (ROOT / "EVALS.md").read_text()
    policies = len({row[0] for row in summary_rows(evals_text)})
    expected = summary_rows(evals_text)[:policies]  # the summary table comes first
    if summary_rows(readme) != expected:
        problems.append("the eval table in README.md differs from the summary in EVALS.md")

    collected = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )  # fmt: skip
    found = re.search(r"(\d+) tests? collected", collected.stdout)
    stated = re.search(r"\*\*(\d+) tests\*\*", readme)
    if not found or not stated or found.group(1) != stated.group(1):
        problems.append(
            f"README.md states {stated.group(1) if stated else 'no'} tests; "
            f"pytest collects {found.group(1) if found else 'an unknown number'}"
        )

    rules = len(re.findall(r"^\| R-\d{3} \|", (ROOT / "docs" / "RULES.md").read_text(), re.M))
    stated_rules = re.search(r"\*\*(\d+) rules\*\*", readme)
    if not stated_rules or int(stated_rules.group(1)) != rules:
        problems.append(f"README.md's rule count is not {rules}")

    for problem in problems:
        print(f"FAIL {problem}")
    if not problems:
        print(f"OK: README.md matches EVALS.md, {found.group(1)} tests and {rules} rules")  # type: ignore[union-attr]
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
