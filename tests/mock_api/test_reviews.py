"""Reviews: approval is a new decision; refusals leave the review pending."""

from __future__ import annotations

from decimal import Decimal

from tests.mock_api.conftest import Mock


def test_approval_is_new_allow_with_supersedes(mock: Mock) -> None:
    """R-052, R-055, R-059: approval issues a fresh allow with `supersedes`; the original stays."""
    _, key, mandate = mock.agent_with_mandate()
    original = mock.review(key, "340.00", metadata={"order_id": "order-4412"})
    mock.clock.advance(minutes=10)

    response = mock.post(f"/v1/reviews/{original['review']['review']}/approve")
    assert response.status_code == 201
    approval = mock.body(response)
    assert approval["verdict"] == "allow"
    assert approval["supersedes"] == original["decision"]
    assert approval["decision"] != original["decision"]
    assert approval["nonce"] != original["nonce"]
    assert approval["mandate"] == mandate["mandate"]
    assert approval["request"] == original["request"]
    assert approval["issued_at"] == "2026-10-27T12:10:00Z"  # when it was approved
    assert approval["expires_at"] == "2026-10-27T12:15:00Z"  # its own five minutes
    assert approval["metadata"] == {"order_id": "order-4412"}

    unchanged = mock.body(mock.get(f"/v1/decisions/{original['decision']}"))
    assert unchanged == original


def test_review_yields_at_most_one_allow(mock: Mock) -> None:
    """R-054: a second approve, or a deny after approval, is 400: the review is closed."""
    _, key, _ = mock.agent_with_mandate()
    review_id = mock.review(key)["review"]["review"]
    assert mock.post(f"/v1/reviews/{review_id}/approve").status_code == 201
    again = mock.post(f"/v1/reviews/{review_id}/approve")
    assert again.status_code == 400
    assert mock.body(again)["error"]["code"] == "invalid_request"
    assert mock.post(f"/v1/reviews/{review_id}/deny").status_code == 400


def test_approval_refused_after_revoke_keeps_review_pending(mock: Mock) -> None:
    """R-053: revoked mandate: 400, no decision issued, and the review can still be denied."""
    _, key, mandate = mock.agent_with_mandate()
    review_id = mock.review(key)["review"]["review"]
    mock.post(f"/v1/mandates/{mandate['mandate']}/revoke")
    before = len(mock.export())

    response = mock.post(f"/v1/reviews/{review_id}/approve")
    assert response.status_code == 400
    assert "revoked" in mock.body(response)["error"]["message"]
    assert len(mock.export()) == before
    assert mock.post(f"/v1/reviews/{review_id}/deny").status_code == 200  # still pending


def test_approval_refused_when_agent_disabled(mock: Mock) -> None:
    """R-053: a disabled agent's review can't be approved until the agent is enabled again."""
    agent, key, _ = mock.agent_with_mandate()
    review_id = mock.review(key)["review"]["review"]
    mock.post(f"/v1/agents/{agent}/disable")
    assert mock.post(f"/v1/reviews/{review_id}/approve").status_code == 400
    mock.post(f"/v1/agents/{agent}/enable")
    assert mock.post(f"/v1/reviews/{review_id}/approve").status_code == 201


def test_approval_refused_when_per_month_used(mock: Mock) -> None:
    """R-053: if other allows used up per_month while the review waited, approval is 400."""
    _, key, _ = mock.agent_with_mandate(
        limits={"per_transaction": Decimal("500"), "per_month": Decimal("500"), "currency": "USD"}
    )
    review_id = mock.review(key, "300.00")["review"]["review"]
    assert mock.decide(key, "250.00")["verdict"] == "allow"
    assert mock.decide(key, "100.00")["verdict"] == "allow"  # 350 used; 350 + 300 > 500
    response = mock.post(f"/v1/reviews/{review_id}/approve")
    assert response.status_code == 400
    assert "per_month" in mock.body(response)["error"]["message"]


def test_review_expires_after_24_hours(mock: Mock) -> None:
    """R-051: 24 hours after creation, the review has expired and can't be approved."""
    _, key, _ = mock.agent_with_mandate()
    review_id = mock.review(key)["review"]["review"]
    mock.clock.advance(hours=24)
    response = mock.post(f"/v1/reviews/{review_id}/approve")
    assert response.status_code == 400
    assert "expired" in mock.body(response)["error"]["message"]


def test_deny_review_returns_closed_review(mock: Mock) -> None:
    """R-056: deny answers 200 with the review object, status denied, and issues no decision."""
    _, key, _ = mock.agent_with_mandate()
    review = mock.review(key)["review"]
    before = len(mock.export())
    response = mock.post(f"/v1/reviews/{review['review']}/deny")
    assert response.status_code == 200
    assert mock.body(response) == {**review, "status": "denied"}
    assert len(mock.export()) == before


def test_reviews_cannot_be_read(mock: Mock) -> None:
    """R-057: there is no review read endpoint; both paths are 404."""
    _, key, _ = mock.agent_with_mandate()
    review_id = mock.review(key)["review"]["review"]
    for path in ("/v1/reviews", f"/v1/reviews/{review_id}"):
        response = mock.get(path)
        assert response.status_code == 404
        assert mock.body(response)["error"]["code"] == "not_found"


def test_approve_needs_org_key(mock: Mock) -> None:
    """R-058: an agent cannot approve its own review."""
    _, key, _ = mock.agent_with_mandate()
    review_id = mock.review(key)["review"]["review"]
    response = mock.post(f"/v1/reviews/{review_id}/approve", key=key)
    assert response.status_code == 403
    assert mock.post(f"/v1/reviews/{review_id}/approve").status_code == 201


def test_approval_refused_when_mandate_expired(mock: Mock) -> None:
    """R-053: if the mandate expired while the review waited, approval is 400 and no
    decision is issued"""
    _, key, _ = mock.agent_with_mandate(expires="2026-10-28")
    review_id = mock.review(key)["review"]["review"]
    before = len(mock.export())
    mock.clock.advance(hours=13)  # 01:00 on the 28th: the mandate has expired, the review hasn't
    response = mock.post(f"/v1/reviews/{review_id}/approve")
    assert response.status_code == 400
    assert "expired" in mock.body(response)["error"]["message"]
    assert len(mock.export()) == before
