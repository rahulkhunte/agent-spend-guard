"""The decision log: NDJSON export, date windows, and append-only storage."""

from __future__ import annotations

import sqlite3

import pytest

from mock_api.store import APPEND_ONLY_TABLES
from tests.mock_api.conftest import Mock


def test_export_is_ndjson_with_tokens(mock: Mock) -> None:
    """R-121, R-125: one decision record per line, verdict_token included; from and to are
    required; the same window exports the same bytes."""
    _, key, _ = mock.agent_with_mandate()
    decisions = [mock.decide(key, amount) for amount in ("10", "720", "340")]
    response = mock.get("/v1/exports/records", **{"from": "2026-10-27", "to": "2026-10-28"})
    assert response.headers["Content-Type"].startswith("application/x-ndjson")
    lines = response.text.splitlines()
    assert len(lines) == 3
    records = mock.export()
    assert records == decisions
    assert all(record["verdict_token"] for record in records)
    again = mock.get("/v1/exports/records", **{"from": "2026-10-27", "to": "2026-10-28"})
    assert again.content == response.content
    assert mock.get("/v1/exports/records", to="2026-10-28").status_code == 400


def test_export_window_from_inclusive_to_exclusive(mock: Mock) -> None:
    """R-122: `from` is inclusive and `to` is exclusive."""
    _, key, _ = mock.agent_with_mandate()
    first = mock.decide(key)
    mock.clock.advance(days=1)
    second = mock.decide(key)
    assert mock.export("2026-10-27", "2026-10-28") == [first]
    assert mock.export("2026-10-28", "2026-10-29") == [second]
    assert mock.export("2026-10-27", "2026-10-29") == [first, second]
    assert mock.export("2026-10-27", "2026-10-27") == []


def test_tables_are_append_only(mock: Mock) -> None:
    """R-123: the database refuses UPDATE and DELETE on every table."""
    # Put at least one row in every table: triggers only fire on rows that exist.
    mock.register_webhook(["decision.review_pending", "decision.resolved", "mandate.revoked"])
    agent, key, mandate = mock.agent_with_mandate()
    review_id = mock.review(key, idem="order-1")["review"]["review"]
    mock.post(f"/v1/reviews/{review_id}/approve")
    mock.post(f"/v1/agents/{agent}/disable")
    mock.post(f"/v1/mandates/{mandate['mandate']}/revoke")
    mock.state.tick()
    conn = mock.state.store.conn
    for table in APPEND_ONLY_TABLES:
        assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] > 0, table

    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("UPDATE decisions SET verdict = 'allow'")
    for table in APPEND_ONLY_TABLES:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(f"DELETE FROM {table}")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(f"UPDATE {table} SET rowid = rowid")


def test_exported_review_stays_pending(mock: Mock) -> None:
    """R-124: after approval, the exported review decision still shows status pending, and the
    approval is a separate record pointing at it."""
    _, key, _ = mock.agent_with_mandate()
    original = mock.review(key)
    approval = mock.body(mock.post(f"/v1/reviews/{original['review']['review']}/approve"))
    records = mock.export()
    assert records == [original, approval]
    assert records[0]["review"]["status"] == "pending"
    assert records[1]["supersedes"] == original["decision"]
