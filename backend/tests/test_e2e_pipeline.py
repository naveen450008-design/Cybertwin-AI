import uuid
import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentEventMapping
from app.models.mitre import IncidentMitreMapping
from app.models.audit import AuditLedger
from app.services.synthetic_service import SyntheticDataService
from app.services.detection_rules import DetectionRuleEngine
from app.services.ueba_service import UEBAService
from app.services.ml_anomaly_service import MLAnomalyService
from app.services.correlation_service import CorrelationService
from app.services.risk_engine import RiskEngine
from app.services.mitre_service import MitreService
from app.services.copilot_service import CopilotService
from app.services.similar_incident_service import SimilarIncidentService
from app.services.blast_radius_service import BlastRadiusService
from app.services.digital_twin_service import DigitalTwinService
from app.services.audit_service import AuditService
from app.services.governance_service import GovernanceService


@pytest.mark.asyncio
async def test_complete_autonomous_cybersecurity_e2e_pipeline(
    client: AsyncClient,
    admin_auth_headers: dict,
    db_session: AsyncSession
):
    """
    Comprehensive End-to-End Test verifying the entire 23-stage autonomous pipeline:
    1. Synthetic Telemetry Generation (Multi-Stage Kill Chain)
    2. Event Ingestion & Persistence
    3. Deterministic Detection Rule Evaluation
    4. UEBA Baseline Comparison
    5. ML Isolation Forest Anomaly Scoring
    6. 15-Minute Sliding Correlation Window
    7. Incident Creation
    8. Canonical 6-Factor Risk Score Calculation
    9. MITRE ATT&CK Technique Mapping
    10. Attack Timeline Extraction
    11. Attack Graph Topology Extraction
    12. Grounded AI Copilot Q&A (FACT vs PREDICTION)
    13. 5D Cosine Similar Incident Search
    14. Blast Radius Disruption Calculation
    15. Digital Twin Safe Response Simulation
    16. Human Approval Gate
    17. Simulation Execution (Zero OS/Network Mutability)
    18. Instant Safe Rollback
    19. Append-Only Audit Ledger Hash-Chaining
    20. Cryptographic Chain Integrity Verification
    21. Analyst Ground-Truth Feedback Submission
    22. Model Governance Precision / Recall / F1 Evaluation
    23. API Surface Validation
    """

    # -------------------------------------------------------------
    # STAGE 1 & 2: Synthetic Telemetry Generation & Ingestion
    # -------------------------------------------------------------
    synthetic_events = await SyntheticDataService.inject_brute_force_scenario(
        db=db_session,
        target_user="alice.smith"
    )
    assert len(synthetic_events) >= 4

    # -------------------------------------------------------------
    # STAGE 3: Deterministic Detection Rule Evaluation
    # -------------------------------------------------------------
    sample_event = {
        "event_id": str(uuid.uuid4()),
        "event_type": "PROCESS_EXECUTION",
        "action": "PROCESS_SPAWN",
        "process_name": "powershell.exe",
        "username": "alice.smith",
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.2.10",
        "status": "SUCCESS",
        "timestamp": datetime.now(timezone.utc)
    }
    fired_rule = DetectionRuleEngine.check_suspicious_process(sample_event)
    assert fired_rule is not None
    assert fired_rule["rule_id"] == "RULE-PROC-001"
    assert fired_rule["mitre_technique"].startswith("T1059")

    # -------------------------------------------------------------
    # STAGE 4: UEBA Evaluation
    # -------------------------------------------------------------
    await UEBAService.update_baseline_with_event(db=db_session, event=sample_event)
    user_baseline = await UEBAService.get_baseline(
        db=db_session,
        entity_type="USER",
        entity_id="alice.smith"
    )
    assert user_baseline is not None
    assert user_baseline["entity_id"] == "alice.smith"

    # -------------------------------------------------------------
    # STAGE 5: ML Isolation Forest Anomaly Scoring
    # -------------------------------------------------------------
    ml_eval = MLAnomalyService.evaluate_anomaly(
        event=sample_event,
        recent_events=[],
        ueba_baseline=None
    )
    assert "anomaly_score" in ml_eval
    assert 0.0 <= ml_eval["anomaly_score"] <= 100.0
    assert ml_eval["label"] == "POTENTIAL ANOMALY"

    # -------------------------------------------------------------
    # STAGE 6 & 7: 15-Minute Correlation & Incident Creation
    # -------------------------------------------------------------
    incident = None
    for ev in synthetic_events:
        inc = await CorrelationService.correlate_event(db=db_session, event=ev)
        if inc:
            incident = inc

    assert incident is not None
    assert incident.status in ["NEW", "OPEN"]
    assert len(incident.event_mappings) >= 1

    # -------------------------------------------------------------
    # STAGE 8: Canonical 6-Factor Risk Score Calculation
    # -------------------------------------------------------------
    assert incident.risk_score >= 0.0
    assert incident.risk_score <= 100.0
    assert incident.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert 0.0 <= incident.anomaly_score <= 100.0
    assert 0.0 <= incident.threat_severity_score <= 100.0
    assert 0.0 <= incident.asset_criticality_score <= 100.0

    # -------------------------------------------------------------
    # STAGE 9: MITRE ATT&CK Mapping
    # -------------------------------------------------------------
    techs = MitreService.map_event_to_techniques(sample_event)
    assert len(techs) >= 1
    assert any(t["technique_id"].startswith("T1059") for t in techs)

    stmt = select(IncidentMitreMapping).where(IncidentMitreMapping.incident_id == incident.incident_id)
    res = await db_session.execute(stmt)
    incident_mitre = res.scalars().all()
    assert len(incident_mitre) >= 1
    mapped_ids = [m.technique_id for m in incident_mitre]
    assert any(tid.startswith("T1") for tid in mapped_ids)

    # -------------------------------------------------------------
    # STAGE 10: Timeline Extraction
    # -------------------------------------------------------------
    resp = await client.get(f"/api/v1/incidents/{incident.incident_id}/timeline", headers=admin_auth_headers)
    assert resp.status_code == 200
    timeline = resp.json()["events"]
    assert len(timeline) >= 1
    assert "timestamp" in timeline[0]
    assert "action" in timeline[0]

    # -------------------------------------------------------------
    # STAGE 11: Attack Graph Topology Extraction
    # -------------------------------------------------------------
    resp = await client.get(f"/api/v1/incidents/{incident.incident_id}/graph", headers=admin_auth_headers)
    assert resp.status_code == 200
    graph = resp.json()
    assert "nodes" in graph
    assert "edges" in graph
    assert len(graph["nodes"]) >= 1

    # -------------------------------------------------------------
    # STAGE 12: Grounded AI Copilot Q&A (FACT vs PREDICTION)
    # -------------------------------------------------------------
    copilot_resp = await CopilotService.investigate_incident(
        db=db_session,
        incident_id=incident.incident_id,
        question="What attack techniques were observed and what is the severity?"
    )
    assert copilot_resp["incident_id"] == str(incident.incident_id)
    assert len(copilot_resp["verified_facts"]) > 0
    assert len(copilot_resp["estimated_predictions"]) > 0
    assert "ESTIMATED PREDICTION" in copilot_resp["compliance_tags"]

    # -------------------------------------------------------------
    # STAGE 13: 5D Cosine Similar Incident Search
    # -------------------------------------------------------------
    similar = await SimilarIncidentService.find_similar_incidents(
        db=db_session,
        target_incident_id=incident.incident_id,
        top_k=5
    )
    assert isinstance(similar, list)

    # -------------------------------------------------------------
    # STAGE 14: Blast Radius Disruption Calculation
    # -------------------------------------------------------------
    blast = BlastRadiusService.calculate_blast_radius(
        action_type="SIMULATE_ISOLATE_DEVICE",
        target_entity_id="dev-wks-012"
    )
    assert 0.0 <= blast.disruption_score <= 100.0
    assert blast.impact_tier in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert blast.summary is not None

    # -------------------------------------------------------------
    # STAGE 15 & 16 & 17: Digital Twin Safe Simulation Execution
    # -------------------------------------------------------------
    twin = DigitalTwinService.get_instance()
    action_id = str(uuid.uuid4())
    sim_exec = twin.execute_simulation(
        action_id=action_id,
        action_type="SIMULATE_ISOLATE_DEVICE",
        target_entity_id="dev-wks-012"
    )
    assert sim_exec["status"] == "EXECUTED_SIMULATION"
    assert sim_exec["marker"] == "SIMULATED ACTION"

    # Verify node is isolated in in-memory Digital Twin
    assert twin.nodes["dev-wks-012"].is_isolated is True

    # -------------------------------------------------------------
    # STAGE 18: Instant Safe Rollback
    # -------------------------------------------------------------
    rollback_res = twin.rollback_simulation(action_id)
    assert rollback_res is True
    assert twin.nodes["dev-wks-012"].is_isolated is False

    # -------------------------------------------------------------
    # STAGE 19: Append-Only Audit Ledger Hash-Chaining
    # -------------------------------------------------------------
    audit_rec = await AuditService.record_mutation(
        db=db_session,
        actor_username="admin",
        actor_role="Security Admin",
        action_taken="SIMULATE_ISOLATE_DEVICE",
        target_entity_type="DEVICE",
        target_entity_id="192.168.1.100",
        old_state={"is_isolated": False},
        new_state={"is_isolated": True},
        session_metadata={"test_run": "e2e_pipeline"}
    )
    assert audit_rec.ledger_index >= 1
    assert len(audit_rec.previous_hash) == 64
    assert len(audit_rec.current_hash) == 64

    # -------------------------------------------------------------
    # STAGE 20: Cryptographic Chain Integrity Verification
    # -------------------------------------------------------------
    verify_report = await AuditService.verify_ledger_integrity(db_session)
    assert verify_report["is_valid"] is True
    assert verify_report["status"] == "INTEGRITY_VERIFIED"
    assert verify_report["corrupted_records_count"] == 0
    assert verify_report["total_records"] >= 1

    # -------------------------------------------------------------
    # STAGE 21 & 22: Analyst Feedback & Model Governance Metrics
    # -------------------------------------------------------------
    feedback = await GovernanceService.record_feedback(
        db=db_session,
        incident_id=incident.incident_id,
        user_id=None,
        verdict="CONFIRMED_THREAT",
        confidence_rating=5,
        analyst_notes="Confirmed multi-attempt credential stuffing attack"
    )
    assert feedback.verdict == "CONFIRMED_THREAT"

    metrics = await GovernanceService.compute_metrics(db_session)
    assert metrics["total_feedback_samples"] >= 1
    assert metrics["precision"] >= 0.0
    assert metrics["recall"] >= 0.0
    assert metrics["f1_score"] >= 0.0
    assert metrics["marker"] == "INTERNAL EVALUATION METRIC"

    # -------------------------------------------------------------
    # STAGE 23: API Surface Validation (HTTP Endpoints)
    # -------------------------------------------------------------
    # GET /api/v1/incidents
    resp = await client.get("/api/v1/incidents", headers=admin_auth_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1

    # GET /api/v1/simulation/topology
    resp = await client.get("/api/v1/simulation/topology", headers=admin_auth_headers)
    assert resp.status_code == 200
    assert "nodes" in resp.json()
    assert resp.json()["marker"] == "SIMULATED ACTION"

    # GET /api/v1/audit/verify
    resp = await client.get("/api/v1/audit/verify", headers=admin_auth_headers)
    assert resp.status_code == 200
    assert resp.json()["is_valid"] is True

    # GET /api/v1/governance/metrics
    resp = await client.get("/api/v1/governance/metrics", headers=admin_auth_headers)
    assert resp.status_code == 200
    assert "f1_score" in resp.json()
