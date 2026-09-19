import pytest
from app.services.governance_service import GovernanceService


@pytest.mark.asyncio
async def test_analyst_feedback_and_metrics_calculation(client, admin_auth_headers):
    # 1. Submit Analyst Feedback
    feed_res = await client.post(
        "/api/v1/governance/feedback",
        json={
            "verdict": "CONFIRMED_THREAT",
            "confidence_rating": 5,
            "analyst_notes": "Ground-truth verified brute-force campaign."
        },
        headers=admin_auth_headers
    )
    assert feed_res.status_code == 200
    fb_data = feed_res.json()
    assert fb_data["verdict"] == "CONFIRMED_THREAT"
    assert fb_data["confidence_rating"] == 5

    # 2. Query Model Governance Metrics
    metrics_res = await client.get("/api/v1/governance/metrics", headers=admin_auth_headers)
    assert metrics_res.status_code == 200
    m_data = metrics_res.json()
    assert m_data["precision"] > 0.0
    assert m_data["recall"] > 0.0
    assert m_data["f1_score"] > 0.0
    assert m_data["marker"] == "INTERNAL EVALUATION METRIC"
    assert m_data["status"] == "ACTIVE"
