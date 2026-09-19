"""Tamper-Evident Hash-Chained Audit Ledger Service.

Strictly implements the cryptographic specification from docs/architecture/06_SECURITY_RBAC_AUDIT.md §3:
    CurrentHash_n = SHA256(PreviousHash_n-1 || Timestamp_n || Actor_n || Action_n || CanonicalPayload_n)
    Genesis Hash  = 0000000000000000000000000000000000000000000000000000000000000000
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLedger


class AuditService:
    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    @classmethod
    def serialize_canonical_payload(
        cls,
        old_state: Dict[str, Any],
        new_state: Dict[str, Any],
        metadata: Dict[str, Any]
    ) -> str:
        """Serializes dictionary to deterministic RFC 8785 canonical JSON string."""
        payload = {
            "metadata": metadata or {},
            "new_state": new_state or {},
            "old_state": old_state or {}
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @classmethod
    def compute_record_hash(
        cls,
        previous_hash: str,
        timestamp_str: str,
        actor_username: str,
        action_taken: str,
        canonical_payload: str
    ) -> str:
        """Computes SHA-256 seal for an individual audit ledger record."""
        pre_image = f"{previous_hash}||{timestamp_str}||{actor_username}||{action_taken}||{canonical_payload}"
        return hashlib.sha256(pre_image.encode("utf-8")).hexdigest()

    @classmethod
    async def record_mutation(
        cls,
        db: AsyncSession,
        actor_username: str,
        actor_role: str,
        action_taken: str,
        target_entity_type: str,
        target_entity_id: str,
        old_state: Optional[Dict[str, Any]] = None,
        new_state: Optional[Dict[str, Any]] = None,
        session_metadata: Optional[Dict[str, Any]] = None
    ) -> AuditLedger:
        """Appends a cryptographically sealed, hash-chained record to the audit ledger."""
        # 1. Fetch latest record to get previous_hash
        latest_stmt = select(AuditLedger).order_by(desc(AuditLedger.ledger_index)).limit(1)
        res = await db.execute(latest_stmt)
        latest_record = res.scalar_one_or_none()

        previous_hash = latest_record.current_hash if latest_record else cls.GENESIS_HASH
        ts = datetime.now(timezone.utc)
        ts_str = str(int(ts.timestamp()))

        # 2. Serialize canonical payload & compute hash
        canon_payload = cls.serialize_canonical_payload(
            old_state or {}, new_state or {}, session_metadata or {}
        )
        current_hash = cls.compute_record_hash(
            previous_hash=previous_hash,
            timestamp_str=ts_str,
            actor_username=actor_username,
            action_taken=action_taken,
            canonical_payload=canon_payload
        )

        # 3. Create and persist record
        audit_record = AuditLedger(
            audit_id=uuid.uuid4(),
            timestamp=ts,
            actor_username=actor_username,
            actor_role=actor_role,
            action_taken=action_taken,
            target_entity_type=target_entity_type,
            target_entity_id=str(target_entity_id),
            old_state_json=old_state or {},
            new_state_json=new_state or {},
            session_metadata=session_metadata or {},
            previous_hash=previous_hash,
            current_hash=current_hash
        )
        db.add(audit_record)
        await db.commit()
        await db.refresh(audit_record)
        return audit_record

    @classmethod
    async def verify_ledger_integrity(cls, db: AsyncSession) -> Dict[str, Any]:
        """Traverses ledger sequentially from genesis to head, verifying chain continuity and SHA-256 seals."""
        stmt = select(AuditLedger).order_by(AuditLedger.ledger_index.asc())
        res = await db.execute(stmt)
        records = res.scalars().all()

        if not records:
            return {
                "status": "VERIFIED_EMPTY",
                "is_valid": True,
                "total_records": 0,
                "corrupted_records_count": 0,
                "genesis_hash": cls.GENESIS_HASH,
                "head_hash": None,
                "verification_timestamp": datetime.now(timezone.utc).isoformat(),
                "details": "Audit ledger is empty."
            }

        expected_previous_hash = cls.GENESIS_HASH
        corrupted_entries = []

        for r in records:
            # Check 1: Chain continuity link
            if r.previous_hash != expected_previous_hash:
                corrupted_entries.append({
                    "ledger_index": r.ledger_index,
                    "audit_id": str(r.audit_id),
                    "error": "CHAIN_BROKEN_DISCONTINUITY",
                    "expected_previous_hash": expected_previous_hash,
                    "actual_previous_hash": r.previous_hash
                })

            # Check 2: Content hash seal validation
            ts_utc = r.timestamp if r.timestamp.tzinfo is not None else r.timestamp.replace(tzinfo=timezone.utc)
            ts_str = str(int(ts_utc.timestamp()))
            canon_payload = cls.serialize_canonical_payload(
                r.old_state_json, r.new_state_json, r.session_metadata
            )
            recalculated_hash = cls.compute_record_hash(
                previous_hash=r.previous_hash,
                timestamp_str=ts_str,
                actor_username=r.actor_username,
                action_taken=r.action_taken,
                canonical_payload=canon_payload
            )

            if recalculated_hash != r.current_hash:
                corrupted_entries.append({
                    "ledger_index": r.ledger_index,
                    "audit_id": str(r.audit_id),
                    "error": "PAYLOAD_OR_RECORD_TAMPERED",
                    "stored_hash": r.current_hash,
                    "recalculated_hash": recalculated_hash
                })

            expected_previous_hash = r.current_hash

        is_valid = len(corrupted_entries) == 0
        return {
            "status": "INTEGRITY_VERIFIED" if is_valid else "TAMPERING_DETECTED",
            "is_valid": is_valid,
            "total_records": len(records),
            "corrupted_records_count": len(corrupted_entries),
            "genesis_hash": cls.GENESIS_HASH,
            "head_hash": records[-1].current_hash,
            "verification_timestamp": datetime.now(timezone.utc).isoformat(),
            "corrupted_entries": corrupted_entries
        }
