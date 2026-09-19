from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.user import User
from app.models.audit import AuditLedger
from app.api.deps import require_any_role
from app.services.audit_service import AuditService
from app.schemas.audit import (
    AuditRecordResponse,
    AuditListResponse,
    AuditVerificationResponse
)

router = APIRouter()


@router.get("/logs", response_model=AuditListResponse)
async def list_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_any_role(["Security Analyst", "Security Admin"])),
    db: AsyncSession = Depends(get_db)
):
    """Retrieves paginated cryptographic audit records."""
    stmt = select(AuditLedger).order_by(desc(AuditLedger.ledger_index)).offset(offset).limit(limit)
    res = await db.execute(stmt)
    records = res.scalars().all()

    count_res = await db.execute(select(AuditLedger))
    total_count = len(count_res.scalars().all())

    return AuditListResponse(total=total_count, records=records)


@router.get("/verify", response_model=AuditVerificationResponse)
async def verify_audit_chain(
    current_user: User = Depends(require_any_role(["Security Analyst", "Security Admin"])),
    db: AsyncSession = Depends(get_db)
):
    """Cryptographically verifies hash continuity and data integrity across the audit ledger."""
    report = await AuditService.verify_ledger_integrity(db)
    return AuditVerificationResponse(**report)


@router.get("/export")
async def export_audit_log(
    current_user: User = Depends(require_any_role(["Security Analyst", "Security Admin"])),
    db: AsyncSession = Depends(get_db)
):
    """Exports the entire cryptographic audit trail for external governance verification."""
    stmt = select(AuditLedger).order_by(AuditLedger.ledger_index.asc())
    res = await db.execute(stmt)
    records = res.scalars().all()

    export_data = [
        {
            "ledger_index": r.ledger_index,
            "audit_id": str(r.audit_id),
            "timestamp": r.timestamp.isoformat(),
            "actor": {"username": r.actor_username, "role": r.actor_role},
            "action": r.action_taken,
            "target": {"type": r.target_entity_type, "id": r.target_entity_id},
            "previous_hash": r.previous_hash,
            "current_hash": r.current_hash,
            "payload": {
                "old_state": r.old_state_json,
                "new_state": r.new_state_json,
                "metadata": r.session_metadata
            }
        }
        for r in records
    ]
    return JSONResponse(
        content={
            "audit_ledger_export": export_data,
            "total_records": len(export_data),
            "genesis_hash": AuditService.GENESIS_HASH,
            "cryptographic_standard": "SHA-256 (FIPS 180-4)"
        }
    )
