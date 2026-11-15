"""Prefixed ids and mock API keys, in the spec's formats."""

from __future__ import annotations

import hashlib
import secrets


def new_id(prefix: str, nbytes: int = 8) -> str:
    """`dec_`, `mnd_`, `rev_`, `n_`, `evt_`, `whk_` or `req_` followed by random hex."""
    return f"{prefix}{secrets.token_hex(nbytes)}"


def new_key(kind: str) -> str:
    """A sandbox key: `ak_sandbox_` or `sk_sandbox_` followed by 32 hex characters."""
    return f"{kind}_sandbox_{secrets.token_hex(16)}"


def key_hash(key: str) -> str:
    """Keys are stored only as a SHA-256 hash (SPEC section 2)."""
    return hashlib.sha256(key.encode()).hexdigest()


def key_hint(key: str) -> str:
    """A safe way to show a key: `sk_sandbox_...7906`."""
    prefix = key[: key.find("_", key.find("_") + 1) + 1]
    return f"{prefix}...{key[-4:]}"
