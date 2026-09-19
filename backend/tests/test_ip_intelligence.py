import pytest
from httpx import AsyncClient
from app.services.ip_intelligence_service import IPIntelligenceService


def test_classify_ip_types():
    """Verify passive RFC-compliant IP address categorization without network probing."""
    # RFC 1918 Private
    t1, is_int1, v1, cidr1 = IPIntelligenceService.classify_ip_type("192.168.1.50")
    assert t1 == "Private"
    assert is_int1 is True
    assert v1 == 4

    t2, is_int2, _, _ = IPIntelligenceService.classify_ip_type("10.0.0.1")
    assert t2 == "Private"
    assert is_int2 is True

    t3, is_int3, _, _ = IPIntelligenceService.classify_ip_type("172.16.5.10")
    assert t3 == "Private"
    assert is_int3 is True

    # Loopback
    tl, is_intl, _, _ = IPIntelligenceService.classify_ip_type("127.0.0.1")
    assert tl == "Loopback"
    assert is_intl is True

    # Public WAN (Simulated External and Real Global)
    t_pub, is_int_pub, _, _ = IPIntelligenceService.classify_ip_type("198.51.100.42")
    assert t_pub == "Public"
    assert is_int_pub is False

    t_pub2, is_int_pub2, _, _ = IPIntelligenceService.classify_ip_type("8.8.8.8")
    assert t_pub2 == "Public"
    assert is_int_pub2 is False

    # Invalid / Unknown
    t_unk, is_int_unk, _, _ = IPIntelligenceService.classify_ip_type("invalid-ip-format")
    assert t_unk == "Unknown"
    assert is_int_unk is False


@pytest.mark.asyncio
async def test_ip_intelligence_endpoints_and_radar(client: AsyncClient, admin_auth_headers: dict):
    """Test full suite of IP Intelligence REST API endpoints."""
    # 1. Seed demo telemetry first
    gen_res = await client.post(
        "/api/v1/demo/generate-suspicious",
        json={"scenario_type": "BRUTE_FORCE", "target_username": "user_05"},
        headers=admin_auth_headers
    )
    assert gen_res.status_code == 200

    # 2. Test summary endpoint
    sum_res = await client.get("/api/v1/ip-intelligence/summary", headers=admin_auth_headers)
    assert sum_res.status_code == 200
    summaries = sum_res.json()
    assert isinstance(summaries, list)
    assert len(summaries) > 0

    # Verify summary fields
    first_sum = summaries[0]
    assert "ip_address" in first_sum
    assert "ip_type" in first_sum
    assert "ip_risk_score" in first_sum
    assert "threat_level" in first_sum

    # 3. Test deep intelligence on observed attacker IP
    target_ip = "198.51.100.42"
    detail_res = await client.get(f"/api/v1/ip-intelligence/details/{target_ip}", headers=admin_auth_headers)
    assert detail_res.status_code == 200
    detail = detail_res.json()

    assert detail["ip_address"] == target_ip
    assert detail["ip_type"] == "Public"
    assert detail["is_internal"] is False
    assert "geo" in detail
    assert "reputation" in detail
    assert "Reputation data unavailable" in detail["reputation"]["status"]
    assert "risk_profile" in detail
    assert detail["risk_profile"]["threat_level"] in ["HIGH", "CRITICAL"]
    assert detail["risk_profile"]["ip_risk_score"] > 0
    assert "timeline" in detail
    assert len(detail["timeline"]) > 0
    assert "entity_graph" in detail
    assert len(detail["entity_graph"]["nodes"]) > 0
    assert "attack_path" in detail
    assert len(detail["attack_path"]) > 0

    # 4. Test Threat Radar endpoint
    radar_res = await client.get("/api/v1/ip-intelligence/threat-radar", headers=admin_auth_headers)
    assert radar_res.status_code == 200
    radar_data = radar_res.json()
    assert radar_data["classification"] == "VISUAL_ANALYTICS_INTERNAL_OBSERVED_ENTITIES"
    assert "entities" in radar_data
    assert len(radar_data["entities"]) > 0
    for entity in radar_data["entities"]:
        assert 0.0 <= entity["angle"] <= 360.0
        assert 10.0 <= entity["distance"] <= 100.0

    # 5. Test Security Health Score endpoint
    score_res = await client.get("/api/v1/ip-intelligence/security-score", headers=admin_auth_headers)
    assert score_res.status_code == 200
    score_data = score_res.json()
    assert 0.0 <= score_data["security_health_score"] <= 100.0
    assert score_data["health_status"] in ["OPTIMAL", "MODERATE", "ELEVATED_RISK", "CRITICAL"]
    assert "factors" in score_data


@pytest.mark.asyncio
async def test_viewer_pii_masking_on_ip_intelligence(client: AsyncClient, viewer_auth_headers: dict, admin_auth_headers: dict):
    """Ensure Viewer role receives masked IPs on IP intelligence endpoints."""
    # Seed events first with admin
    await client.post(
        "/api/v1/demo/generate-suspicious",
        json={"scenario_type": "BRUTE_FORCE", "target_username": "user_05"},
        headers=admin_auth_headers
    )

    sum_res = await client.get("/api/v1/ip-intelligence/summary", headers=viewer_auth_headers)
    assert sum_res.status_code == 200
    summaries = sum_res.json()
    assert len(summaries) > 0
    for s in summaries:
        if "." in s["ip_address"]:
            # Must be masked for pure Viewer
            assert "***" in s["ip_address"]
