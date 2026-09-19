import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict, field_validator


VALID_EVENT_TYPES = {
    "AUTHENTICATION",
    "NETWORK_CONNECTION",
    "PROCESS_EXECUTION",
    "FILE_ACCESS",
    "DATA_TRANSFER",
    "PRIVILEGE_CHANGE"
}

VALID_STATUSES = {"SUCCESS", "FAILURE", "DENIED", "ERROR"}

VALID_SEVERITIES = {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

VALID_AUTH_METHODS = {"PASSWORD", "MFA", "SSH_KEY", "KERBEROS", "TOKEN", "NONE"}


class EventCreateRequest(BaseModel):
    timestamp: datetime = Field(..., description="ISO-8601 UTC timestamp")
    username: Optional[str] = Field(None, max_length=128)
    user_id: Optional[uuid.UUID] = None
    source_ip: Optional[str] = Field(None, max_length=45)
    destination_ip: Optional[str] = Field(None, max_length=45)
    device_id: Optional[str] = Field(None, max_length=128)
    device_name: Optional[str] = Field(None, max_length=128)
    server_id: Optional[str] = Field(None, max_length=128)
    event_type: str = Field(..., description="Canonical event category")
    action: str = Field(..., max_length=128)
    status: str = Field(..., max_length=32)
    severity: str = Field(..., max_length=32)
    process_name: Optional[str] = Field(None, max_length=256)
    data_volume: Optional[int] = Field(None, ge=0)
    location: Optional[str] = Field(None, max_length=128)
    authentication_method: Optional[str] = Field("NONE", max_length=32)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, v: str) -> str:
        v_upper = v.upper()
        if v_upper not in VALID_EVENT_TYPES:
            raise ValueError(f"Invalid event_type '{v}'. Must be one of {VALID_EVENT_TYPES}")
        return v_upper

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        v_upper = v.upper()
        if v_upper not in VALID_STATUSES:
            raise ValueError(f"Invalid status '{v}'. Must be one of {VALID_STATUSES}")
        return v_upper

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        v_upper = v.upper()
        if v_upper not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{v}'. Must be one of {VALID_SEVERITIES}")
        return v_upper


class EventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: uuid.UUID
    timestamp: datetime
    username: Optional[str] = None
    user_id: Optional[uuid.UUID] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    device_id: Optional[str] = None
    device_name: Optional[str] = None
    server_id: Optional[str] = None
    event_type: str
    action: str
    status: str
    severity: str
    process_name: Optional[str] = None
    data_volume: Optional[int] = None
    location: Optional[str] = None
    authentication_method: str
    metadata_json: Dict[str, Any]
    event_hash: str
    created_at: datetime


class EventBatchIngestResponse(BaseModel):
    batch_id: uuid.UUID
    total_received: int
    valid_events: int
    invalid_events: int
    duplicate_events: int
    stored_events: int
    processing_status: str
    alerts_generated: int = 0
    dataset_marker: str = "SYNTHETIC DATA"


class EventListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: List[EventResponse]
