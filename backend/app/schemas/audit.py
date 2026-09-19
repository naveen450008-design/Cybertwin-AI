from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid


class AuditRecordResponse(BaseModel):
    ledger_index: int
    audit_id: uuid.UUID
    timestamp: datetime
    actor_username: str
    actor_role: str
    action_taken: str
    target_entity_type: str
    target_entity_id: str
    old_state_json: Dict[str, Any] = {}
    new_state_json: Dict[str, Any] = {}
    session_metadata: Dict[str, Any] = {}
    previous_hash: str
    current_hash: str

    model_config = ConfigDict(from_attributes=True)


class AuditListResponse(BaseModel):
    total: int
    records: List[AuditRecordResponse]


class AuditVerificationResponse(BaseModel):
    status: str
    is_valid: bool
    total_records: int
    corrupted_records_count: int
    genesis_hash: str
    head_hash: Optional[str] = None
    verification_timestamp: str
    corrupted_entries: List[Dict[str, Any]] = []
