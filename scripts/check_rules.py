"""Check docs/RULES.md against docs/SPEC.md, the code and the tests.

    python scripts/check_rules.py

For every row `| R-xxx | rule | spec section | implemented in | tests |` it fails if:
- the spec cell has no link `(SPEC.md#anchor)`, or the anchor isn't a heading in docs/SPEC.md
- the implementation or test column is empty
- a cited `path:function` doesn't exist
- a cited `tests/...py::test_name` doesn't exist, or its docstring doesn't name the rule id

It needs nothing but the repo, so it runs in CI.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "docs" / "RULES.md"
SPEC = ROOT / "docs" / "SPEC.md"


def heading_anchor(title: str) -> str:
    """The anchor GitHub gives a markdown heading: lower case, punctuation dropped,
    spaces turned into hyphens. `6.4 Unknown codes` becomes `64-unknown-codes`."""
    kept = re.sub(r"[^a-z0-9 _-]", "", title.strip().lower())
    return kept.replace(" ", "-")


def spec_anchors(text: str) -> set[str]:
    return {
        heading_anchor(match.group(1))
        for match in re.finditer(r"^#{1,6} (.+)$", text, flags=re.MULTILINE)
    }


def defined_names(path: Path) -> dict[str, str | None]:
    """Every function and class name in a file, mapped to its docstring."""
    tree = ast.parse(path.read_text())
    names: dict[str, str | None] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names[node.name] = ast.get_docstring(node)
    return names


def split_refs(cell: str) -> list[str]:
    return [ref.strip(" `") for ref in re.split(r",|<br>", cell) if ref.strip(" `")]


def check_spec(rule_id: str, cell: str, anchors: set[str]) -> list[str]:
    links = re.findall(r"\(SPEC\.md#([^)]+)\)", cell)
    if not links:
        return [f"{rule_id}: no link to a section of docs/SPEC.md"]
    return [
        f"{rule_id}: docs/SPEC.md has no heading with anchor #{anchor}"
        for anchor in links
        if anchor not in anchors
    ]


def check_impl(rule_id: str, cell: str) -> list[str]:
    refs = split_refs(cell)
    if not refs:
        return [f"{rule_id}: no implementation listed"]
    problems = []
    for ref in refs:
        path_text, _, name = ref.partition(":")
        path = ROOT / path_text
        if not path.is_file():
            problems.append(f"{rule_id}: implementation file missing: {path_text}")
        elif name and name.split(".")[-1] not in defined_names(path):
            problems.append(f"{rule_id}: {name} not defined in {path_text}")
    return problems


def check_tests(rule_id: str, cell: str) -> list[str]:
    refs = split_refs(cell)
    if not refs:
        return [f"{rule_id}: no test listed"]
    problems = []
    for ref in refs:
        path_text, _, name = ref.partition("::")
        path = ROOT / path_text
        if not path.is_file() or not name:
            problems.append(f"{rule_id}: test reference must be tests/...py::test_name: {ref}")
            continue
        names = defined_names(path)
        if name not in names:
            problems.append(f"{rule_id}: test missing: {ref}")
        elif rule_id not in (names[name] or ""):
            problems.append(f"{rule_id}: docstring of {name} does not mention {rule_id}")
    return problems


def parse_rows(text: str) -> list[list[str]]:
    rows = []
    for line in text.splitlines():
        if re.match(r"^\|\s*R-\d{3}\s*\|", line):
            rows.append([cell.strip() for cell in line.strip().strip("|").split("|")])
    return rows


def main() -> int:
    anchors = spec_anchors(SPEC.read_text())
    rows = parse_rows(RULES.read_text())
    problems: list[str] = []
    seen: set[str] = set()
    for cells in rows:
        if len(cells) != 5:
            problems.append(f"row has {len(cells)} columns, expected 5: {cells[0]}")
            continue
        rule_id, _rule, spec, impl, tests = cells
        if rule_id in seen:
            problems.append(f"{rule_id}: duplicate id")
        seen.add(rule_id)
        problems += check_spec(rule_id, spec, anchors)
        problems += check_impl(rule_id, impl)
        problems += check_tests(rule_id, tests)

    print(f"{len(rows)} rules checked against docs/SPEC.md, the code and the tests")
    for problem in problems:
        print(f"  FAIL {problem}")
    if not problems:
        print("OK: every rule has a spec section, an implementation and a test")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
