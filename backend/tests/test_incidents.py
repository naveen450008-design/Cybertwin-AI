import pytest
import uuid
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.models.event import SecurityEvent
from app.models.asset import Asset
from app.services.correlation_service import CorrelationService


@pytest.mark.asyncio
async def test_incident_correlation_and_lifecycle(db_session, client, admin_auth_headers):
    # 1. Create an asset
    asset = Asset(
        asset_name="DEV-WKS-TEST",
        asset_type="WORKSTATION",
        criticality_score=40,
        ip_address="192.168.1.50"
    )
    db_session.add(asset)
    await db_session.flush()

    # 2. Create an alert event
    event1 = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        username="alex.chen",
        source_ip="198.51.100.22",
        device_id="DEV-WKS-TEST",
        device_name="DEV-WKS-TEST",
        event_type="FAILED_LOGIN",
        action="AUTHENTICATE_FAILURE",
        status="FAILURE",
        severity="HIGH",
        metadata_json={"detection_rule_id": "RULE-AUTH-001", "ml_anomaly_score": 75.0},
        event_hash="test_hash_event_1"
    )
    db_session.add(event1)
    await db_session.commit()

    # 3. Correlate event 1
    incident = await CorrelationService.correlate_event(db_session, event1)
    assert incident is not None
    assert incident.status == "NEW"
    assert incident.severity == "HIGH"
    assert incident.risk_score > 0
    assert len(incident.mitre_mappings) >= 1

    # 4. Create a second correlated event for the same user within 5 minutes
    event2 = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        username="alex.chen",
        source_ip="198.51.100.22",
        device_id="DEV-WKS-TEST",
        device_name="DEV-WKS-TEST",
        event_type="PROCESS_SPAWN",
        action="EXECUTE_BINARY",
        status="SUCCESS",
        severity="CRITICAL",
        process_name="powershell.exe",
        metadata_json={"detection_rule_id": "RULE-PROC-001", "ml_anomaly_score": 85.0},
        event_hash="test_hash_event_2"
    )
    db_session.add(event2)
    await db_session.commit()

    incident_updated = await CorrelationService.correlate_event(db_session, event2)
    assert incident_updated is not None
    assert incident_updated.incident_id == incident.incident_id
    assert len(incident_updated.event_mappings) == 2

    # 5. Query via API
    headers = admin_auth_headers
    
    # List incidents
    list_res = await client.get("/api/v1/incidents", headers=headers)
    assert list_res.status_code == 200
    data = list_res.json()
    assert data["total"] >= 1
    assert any(inc["incident_id"] == str(incident.incident_id) for inc in data["incidents"])

    # Get single incident
    get_res = await client.get(f"/api/v1/incidents/{incident.incident_id}", headers=headers)
    assert get_res.status_code == 200
    inc_data = get_res.json()
    assert inc_data["event_count"] == 2
    assert len(inc_data["mitre_techniques"]) >= 1

    # Timeline endpoint
    timeline_res = await client.get(f"/api/v1/incidents/{incident.incident_id}/timeline", headers=headers)
    assert timeline_res.status_code == 200
    tl_data = timeline_res.json()
    assert len(tl_data["events"]) == 2

    # Attack graph endpoint
    graph_res = await client.get(f"/api/v1/incidents/{incident.incident_id}/graph", headers=headers)
    assert graph_res.status_code == 200
    graph_data = graph_res.json()
    assert len(graph_data["nodes"]) >= 2
    assert len(graph_data["edges"]) >= 1

    # Status update lifecycle
    patch_res = await client.patch(
        f"/api/v1/incidents/{incident.incident_id}/status",
        json={"status": "INVESTIGATING", "notes": "Analyst assigned"},
        headers=headers
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "INVESTIGATING"
