import pytest
import uuid
from datetime import datetime, timezone
from app.models.incident import Incident, IncidentEventMapping
from app.models.event import SecurityEvent
from app.models.mitre import MitreTechnique, IncidentMitreMapping
from app.services.copilot_service import CopilotService
from app.services.similar_incident_service import SimilarIncidentService


@pytest.mark.asyncio
async def test_copilot_grounded_investigation(db_session, client, admin_auth_headers):
    # 1. Create test incident with event
    inc_id = uuid.uuid4()
    ev_id = uuid.uuid4()
    event = SecurityEvent(
        event_id=ev_id,
        timestamp=datetime.now(timezone.utc),
        username="alex.chen",
        source_ip="198.51.100.22",
        device_name="WS-FINANCE-CHEN",
        event_type="PROCESS_SPAWN",
        action="EXECUTE_BINARY",
        status="SUCCESS",
        severity="CRITICAL",
        process_name="powershell.exe",
        metadata_json={"detection_rule_id": "RULE-PROC-001"},
        event_hash="test_copilot_hash_1"
    )
    db_session.add(event)

    incident = Incident(
        incident_id=inc_id,
        incident_title="Suspicious PowerShell Execution Campaign",
        status="NEW",
        severity="CRITICAL",
        risk_score=85.0,
        anomaly_score=78.0,
        threat_severity_score=100,
        asset_criticality_score=40,
        identity_sensitivity_score=50,
        event_sequence_score=20,
        attack_stage_score=70,
        confidence_score=0.95,
        evidence_quality="HIGH"
    )
    db_session.add(incident)
    await db_session.flush()

    mapping = IncidentEventMapping(
        incident_id=inc_id,
        event_id=ev_id,
        correlation_reason="PowerShell novelty execution"
    )
    db_session.add(mapping)
    await db_session.commit()

    # 2. Query Copilot via API
    res = await client.post(
        "/api/v1/copilot/query",
        json={"incident_id": str(inc_id), "question": "What happened?"},
        headers=admin_auth_headers
    )
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == str(inc_id)
    assert len(data["verified_facts"]) >= 1
    assert data["verified_facts"][0]["type"] == "FACT / EVIDENCE"
    assert len(data["estimated_predictions"]) >= 1
    assert data["estimated_predictions"][0]["type"] == "ESTIMATED PREDICTION"
    assert "SIMULATE" in data["recommended_simulated_action"]


@pytest.mark.asyncio
async def test_similar_incidents_cosine_similarity(db_session, client, admin_auth_headers):
    id1 = uuid.uuid4()
    id2 = uuid.uuid4()

    inc1 = Incident(
        incident_id=id1,
        incident_title="Initial Phishing Incident",
        status="CLOSED",
        severity="HIGH",
        risk_score=75.0,
        anomaly_score=60.0,
        threat_severity_score=75,
        asset_criticality_score=40,
        identity_sensitivity_score=50,
        event_sequence_score=30,
        attack_stage_score=50,
        confidence_score=0.85,
        evidence_quality="MEDIUM"
    )
    inc2 = Incident(
        incident_id=id2,
        incident_title="Secondary Phishing Incident",
        status="RESOLVED",
        severity="HIGH",
        risk_score=72.0,
        anomaly_score=58.0,
        threat_severity_score=75,
        asset_criticality_score=40,
        identity_sensitivity_score=50,
        event_sequence_score=25,
        attack_stage_score=50,
        confidence_score=0.85,
        evidence_quality="MEDIUM"
    )
    db_session.add_all([inc1, inc2])
    await db_session.commit()

    # Query similar incidents for id1
    res = await client.get(f"/api/v1/copilot/similar/{id1}", headers=admin_auth_headers)
    assert res.status_code == 200
    sim_list = res.json()
    assert len(sim_list) >= 1
    assert sim_list[0]["incident_id"] == str(id2)
    assert sim_list[0]["similarity_score"] > 0.90
