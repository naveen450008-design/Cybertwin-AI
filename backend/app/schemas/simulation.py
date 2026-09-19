from pydantic import BaseModel, ConfigDict
from typing import Optional, Dict, Any, List
from datetime import datetime
import uuid


class BlastRadiusRequest(BaseModel):
    action_type: str  # SIMULATE_BLOCK_IP, SIMULATE_ISOLATE_DEVICE, SIMULATE_TERMINATE_SESSION, SIMULATE_RESTRICT_ACCESS
    target_entity_id: str
    incident_id: Optional[uuid.UUID] = None


class BlastRadiusResponse(BaseModel):
    action_type: str
    target_entity_id: str
    disruption_score: float
    severed_sessions_count: int
    collateral_users_count: int
    tier1_disrupted: bool
    estimated_risk_reduction_pct: float
    recommended_mode: str
    impact_tier: str
    summary: str
    marker: str = "SIMULATED ACTION"


class SimulationActionCreateRequest(BaseModel):
    action_type: str
    target_entity_type: str  # IP, DEVICE, USER
    target_entity_id: str
    incident_id: Optional[uuid.UUID] = None
    response_mode: str = "RECOMMEND"


class SimulationActionResponse(BaseModel):
    action_id: uuid.UUID
    incident_id: Optional[uuid.UUID] = None
    action_type: str
    target_entity_type: str
    target_entity_id: str
    response_mode: str
    approval_status: str
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    blast_radius_impact: Dict[str, Any] = {}
    is_reverted: bool = False
    executed_at: Optional[datetime] = None
    created_at: datetime
    marker: str = "SIMULATED ACTION"

    model_config = ConfigDict(from_attributes=True)


class TopologyResponse(BaseModel):
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    marker: str = "SIMULATED ACTION"
    safety_invariant: str
