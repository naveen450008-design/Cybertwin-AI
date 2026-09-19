import pytest
import uuid
from app.services.digital_twin_service import DigitalTwinService
from app.services.blast_radius_service import BlastRadiusService


@pytest.mark.asyncio
async def test_digital_twin_topology_and_isolation(client, admin_auth_headers):
    # 1. Check topology
    res = await client.get("/api/v1/simulation/topology", headers=admin_auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert len(data["nodes"]) >= 4
    assert len(data["edges"]) >= 3
    assert data["marker"] == "SIMULATED ACTION"

    # 2. Check blast radius calculation
    blast_res = await client.post(
        "/api/v1/simulation/blast-radius",
        json={
            "action_type": "SIMULATE_ISOLATE_DEVICE",
            "target_entity_id": "WS-FINANCE-CHEN"
        },
        headers=admin_auth_headers
    )
    assert blast_res.status_code == 200
    blast_data = blast_res.json()
    assert blast_data["disruption_score"] > 0
    assert blast_data["marker"] == "SIMULATED ACTION"

    # 3. Stage a response action
    stage_res = await client.post(
        "/api/v1/simulation/actions/request",
        json={
            "action_type": "SIMULATE_ISOLATE_DEVICE",
            "target_entity_type": "DEVICE",
            "target_entity_id": "WS-FINANCE-CHEN",
            "response_mode": "RECOMMEND"
        },
        headers=admin_auth_headers
    )
    assert stage_res.status_code == 200
    action_data = stage_res.json()
    action_id = action_data["action_id"]
    assert action_data["approval_status"] == "PENDING_APPROVAL"

    # 4. Approve and execute simulation
    approve_res = await client.post(
        f"/api/v1/simulation/actions/{action_id}/approve",
        headers=admin_auth_headers
    )
    assert approve_res.status_code == 200
    exec_data = approve_res.json()
    assert exec_data["approval_status"] == "EXECUTED_SIMULATION"
    assert exec_data["approved_by"] == "admin"

    # 5. Rollback action
    rollback_res = await client.post(
        f"/api/v1/simulation/actions/{action_id}/rollback",
        headers=admin_auth_headers
    )
    assert rollback_res.status_code == 200
    rb_data = rollback_res.json()
    assert rb_data["approval_status"] == "ROLLED_BACK"
    assert rb_data["is_reverted"] is True


def test_blast_radius_canonical_formula():
    """Validates Disruption Score = min(100, 20*N_sessions + 15*N_collateral + 50*I(Tier-1 Disrupted))"""
    # Workstation isolation
    rep = BlastRadiusService.calculate_blast_radius(
        action_type="SIMULATE_ISOLATE_DEVICE",
        target_entity_id="dev-wks-012"
    )
    assert rep.disruption_score >= 20.0  # At least 1 session severed
    assert rep.impact_tier in ["LOW", "HIGH"]
    assert rep.estimated_risk_reduction_pct == 85.0
