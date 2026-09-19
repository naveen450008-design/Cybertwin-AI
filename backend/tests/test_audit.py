import pytest
from app.services.audit_service import AuditService
from app.models.audit import AuditLedger
from sqlalchemy import select


@pytest.mark.asyncio
async def test_audit_hash_chain_and_verification(db_session, client, admin_auth_headers):
    # 1. Verify initial state
    verify_res = await client.get("/api/v1/audit/verify", headers=admin_auth_headers)
    assert verify_res.status_code == 200
    assert verify_res.json()["is_valid"] is True

    # 2. Record mutation 1
    r1 = await AuditService.record_mutation(
        db=db_session,
        actor_username="admin",
        actor_role="Security Admin",
        action_taken="SIMULATE_ISOLATE_DEVICE",
        target_entity_type="DEVICE",
        target_entity_id="DEV-WKS-012",
        old_state={"is_isolated": False},
        new_state={"is_isolated": True}
    )
    assert r1.previous_hash == AuditService.GENESIS_HASH
    assert len(r1.current_hash) == 64

    # 3. Record mutation 2
    r2 = await AuditService.record_mutation(
        db=db_session,
        actor_username="analyst_jane",
        actor_role="Security Analyst",
        action_taken="SIMULATE_BLOCK_IP",
        target_entity_type="IP",
        target_entity_id="198.51.100.22",
        old_state={"is_blocked": False},
        new_state={"is_blocked": True}
    )
    assert r2.previous_hash == r1.current_hash
    assert len(r2.current_hash) == 64

    # 4. Cryptographically verify chain integrity
    verify_after = await client.get("/api/v1/audit/verify", headers=admin_auth_headers)
    assert verify_after.status_code == 200
    report = verify_after.json()
    assert report["is_valid"] is True
    assert report["status"] == "INTEGRITY_VERIFIED"
    assert report["total_records"] >= 2
    assert report["corrupted_records_count"] == 0

    # 5. List logs
    logs_res = await client.get("/api/v1/audit/logs", headers=admin_auth_headers)
    assert logs_res.status_code == 200
    assert logs_res.json()["total"] >= 2

    # 6. Export logs
    export_res = await client.get("/api/v1/audit/export", headers=admin_auth_headers)
    assert export_res.status_code == 200
    assert export_res.json()["total_records"] >= 2


@pytest.mark.asyncio
async def test_audit_tampering_detection(db_session):
    """Artificially tampers with an audit record to verify cryptographic anomaly detection."""
    # Append two records
    r1 = await AuditService.record_mutation(
        db=db_session,
        actor_username="admin",
        actor_role="Security Admin",
        action_taken="TEST_ACTION_A",
        target_entity_type="TEST",
        target_entity_id="1"
    )
    r2 = await AuditService.record_mutation(
        db=db_session,
        actor_username="admin",
        actor_role="Security Admin",
        action_taken="TEST_ACTION_B",
        target_entity_type="TEST",
        target_entity_id="2"
    )

    # Tamper with r1's current_hash directly in DB
    r1.current_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    await db_session.commit()

    # Verify tampering is caught
    report = await AuditService.verify_ledger_integrity(db_session)
    assert report["is_valid"] is False
    assert report["status"] == "TAMPERING_DETECTED"
    assert report["corrupted_records_count"] >= 1
