from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid


class MitreTechniqueSummary(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float

    model_config = ConfigDict(from_attributes=True)


class IncidentResponse(BaseModel):
    incident_id: uuid.UUID
    incident_title: str
    status: str
    severity: str
    risk_score: float
    anomaly_score: float
    threat_severity_score: int
    asset_criticality_score: int
    identity_sensitivity_score: int
    event_sequence_score: int
    attack_stage_score: int
    confidence_score: float
    evidence_quality: str
    assigned_analyst: Optional[str] = None
    sla_breach_deadline: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    event_count: int = 0
    mitre_techniques: List[MitreTechniqueSummary] = []

    model_config = ConfigDict(from_attributes=True)


class IncidentListResponse(BaseModel):
    total: int
    incidents: List[IncidentResponse]


class IncidentStatusUpdateRequest(BaseModel):
    status: str  # NEW, INVESTIGATING, CONTAINMENT_RECOMMENDED, RESPONSE_PENDING, CONTAINED, RESOLVED, FALSE_POSITIVE, CLOSED
    assigned_analyst: Optional[str] = None
    notes: Optional[str] = None


class IncidentTimelineItem(BaseModel):
    event_id: uuid.UUID
    timestamp: datetime
    event_type: str
    action: str
    severity: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    device_name: Optional[str] = None
    correlation_reason: str
    sequence_index: int


class IncidentTimelineResponse(BaseModel):
    incident_id: uuid.UUID
    events: List[IncidentTimelineItem]


class GraphNode(BaseModel):
    id: str
    type: str  # 'attacker_ip', 'user', 'device', 'server', 'database'
    label: str
    metadata: Dict[str, Any] = {}


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str


class IncidentGraphResponse(BaseModel):
    incident_id: uuid.UUID
    nodes: List[GraphNode]
    edges: List[GraphEdge]
