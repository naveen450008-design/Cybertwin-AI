import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class IPRiskProfileBreakdown(BaseModel):
    ip_risk_score: float = Field(..., ge=0.0, le=100.0, description="Derived IP Risk Profile score")
    threat_level: str = Field(..., description="LOW, MEDIUM, HIGH, or CRITICAL")
    event_volume_score: float = Field(..., ge=0.0, le=100.0)
    anomaly_factor_score: float = Field(..., ge=0.0, le=100.0)
    incident_factor_score: float = Field(..., ge=0.0, le=100.0)
    severity_factor_score: float = Field(..., ge=0.0, le=100.0)
    mitre_factor_score: float = Field(..., ge=0.0, le=100.0)
    formula_documentation: str = Field(..., description="Documentation of the derived formula")
    evidence_source: str = Field("INTERNAL_SECURITY_EVIDENCE", description="Origin of intelligence")


class IPBehaviourProfile(BaseModel):
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_events: int = 0
    total_anomalies: int = 0
    total_incidents: int = 0
    associated_users: List[str] = Field(default_factory=list)
    associated_devices: List[str] = Field(default_factory=list)
    associated_servers: List[str] = Field(default_factory=list)
    associated_mitre_techniques: List[str] = Field(default_factory=list)


class IPActivityTimelineItem(BaseModel):
    event_id: uuid.UUID
    timestamp: datetime
    event_type: str
    action: str
    severity: str
    status: str
    username: Optional[str] = None
    destination_ip: Optional[str] = None
    device_name: Optional[str] = None
    server_id: Optional[str] = None
    process_name: Optional[str] = None
    is_anomaly: bool = False
    anomaly_score: Optional[float] = None
    detection_rule_id: Optional[str] = None
    incident_ids: List[str] = Field(default_factory=list)


class IPEntityNode(BaseModel):
    id: str
    type: str  # 'ip', 'user', 'device', 'server', 'incident', 'mitre'
    label: str
    severity: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IPEntityEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str


class IPEntityRelationshipGraph(BaseModel):
    nodes: List[IPEntityNode] = Field(default_factory=list)
    edges: List[IPEntityEdge] = Field(default_factory=list)


class IPAttackPathStep(BaseModel):
    step_number: int
    stage_name: str
    entity_type: str
    entity_name: str
    description: str
    timestamp: Optional[datetime] = None
    severity: str = "INFORMATIONAL"


class IPClusterItem(BaseModel):
    related_ip: str
    ip_type: str
    relationship_type: str  # e.g. "Observed relationship (Shared incident)"
    shared_incidents_count: int
    shared_targets_count: int
    last_co_occurrence: Optional[datetime] = None


class IPIntelligenceSummary(BaseModel):
    ip_address: str
    ip_type: str  # 'Private', 'Public', 'Loopback', 'Reserved', 'Unknown'
    is_internal: bool
    version: int = 4
    total_events: int
    total_anomalies: int
    total_incidents: int
    ip_risk_score: float
    threat_level: str
    primary_location: Optional[str] = None
    last_seen: Optional[datetime] = None


class IPIntelligenceDetail(BaseModel):
    ip_address: str
    ip_type: str
    is_internal: bool
    version: int
    cidr_classification: str
    
    # Passive Geo Metadata
    geo: Dict[str, Any] = Field(
        default_factory=dict,
        description="Passive approximate geo information from ingested telemetry"
    )
    
    # Network Info
    network: Dict[str, Any] = Field(
        default_factory=dict,
        description="Passive network information: ASN, ISP, hostname"
    )
    
    # Reputation
    reputation: Dict[str, Any] = Field(
        default_factory=dict,
        description="Passive reputation status or configured provider disclosure"
    )
    
    # Derived Evidence-Based Risk Profile
    risk_profile: IPRiskProfileBreakdown
    
    # Behaviour Profile
    behaviour: IPBehaviourProfile
    
    # Chronological Activity Timeline
    timeline: List[IPActivityTimelineItem]
    
    # Interactive Entity Relationships
    entity_graph: IPEntityRelationshipGraph
    
    # Step-by-Step Attack Path
    attack_path: List[IPAttackPathStep]
    
    # Observed Co-occurring Clusters
    related_clusters: List[IPClusterItem]


class ThreatRadarEntity(BaseModel):
    id: str
    entity_type: str  # 'IP', 'INCIDENT', 'USER', 'DEVICE'
    label: str
    threat_score: float  # 0 to 100
    severity: str
    distance: float  # 10 to 90 (smaller distance = higher risk/closer to center)
    angle: float     # 0 to 360 degrees
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ThreatRadarResponse(BaseModel):
    classification: str = "VISUAL_ANALYTICS_INTERNAL_OBSERVED_ENTITIES"
    description: str = "Polar radar mapping of internal observed security entities"
    entities: List[ThreatRadarEntity]
    total_tracked: int


class SecurityHealthScoreResponse(BaseModel):
    security_health_score: float = Field(..., ge=0.0, le=100.0)
    health_status: str  # 'OPTIMAL', 'MODERATE', 'ELEVATED_RISK', 'CRITICAL'
    formula_documentation: str
    factors: Dict[str, float]
    active_incidents_count: int
    critical_incidents_count: int
    total_anomalies_count: int
    high_risk_ips_count: int
