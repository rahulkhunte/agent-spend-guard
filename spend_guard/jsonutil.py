"""JSON that keeps money exact.

Amounts are `Decimal` everywhere and never pass through a float:
- `loads` parses every JSON number with a decimal point as `Decimal`.
- `dumps` writes `Decimal` as a plain JSON number and refuses floats outright.

Whole numbers stay `int`, so `iat` and `exp` claims remain integers. Code that
reads an amount converts it with `to_decimal`, which accepts int or Decimal.
"""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not a valid JSON number")


def loads(data: str | bytes) -> Any:
    return json.loads(data, parse_float=Decimal, parse_constant=_reject_constant)


def decimal_text(value: Decimal) -> str:
    """Plain decimal notation without trailing zeros: Decimal("340.00") -> "340"."""
    if not value.is_finite():
        raise ValueError("amounts must be finite")
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return "0" if text in ("", "-0") else text


def dumps(value: Any) -> str:
    """Serialize dicts, lists, strings, ints, bools, None and Decimal. Floats are refused."""
    if isinstance(value, Decimal):
        return decimal_text(value)
    if isinstance(value, float):
        raise TypeError("floats are not allowed; use Decimal for amounts")
    if value is None or isinstance(value, (bool, int, str)):
        return json.dumps(value)
    if isinstance(value, dict):
        items = (f"{json.dumps(str(key))}:{dumps(item)}" for key, item in value.items())
        return "{" + ",".join(items) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(dumps(item) for item in value) + "]"
    raise TypeError(f"cannot serialize {type(value).__name__}")


def to_decimal(value: Any) -> Decimal:
    """Convert a parsed JSON number (int or Decimal) to Decimal. Rejects bools, strings, floats."""
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise ValueError("expected a JSON number")
    return Decimal(value)
