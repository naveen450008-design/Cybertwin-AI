import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.models.user import User
from app.models.incident import Incident, IncidentEventMapping
from app.models.mitre import IncidentMitreMapping, MitreTechnique
from app.models.event import SecurityEvent
from app.api.deps import get_current_user, require_role, require_any_role
from app.schemas.incident import (
    IncidentResponse,
    IncidentListResponse,
    IncidentStatusUpdateRequest,
    IncidentTimelineResponse,
    IncidentTimelineItem,
    IncidentGraphResponse,
    GraphNode,
    GraphEdge,
    MitreTechniqueSummary
)

router = APIRouter()

ALLOWED_STATUSES = {
    "NEW",
    "INVESTIGATING",
    "CONTAINMENT_RECOMMENDED",
    "RESPONSE_PENDING",
    "CONTAINED",
    "RESOLVED",
    "FALSE_POSITIVE",
    "CLOSED"
}


@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity_filter: Optional[str] = Query(None, alias="severity"),
    min_risk: Optional[float] = Query(None, ge=0.0, le=100.0),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Lists security incidents with composite risk scores and MITRE ATT&CK tags."""
    query = (
        select(Incident)
        .options(
            selectinload(Incident.event_mappings),
            selectinload(Incident.mitre_mappings).selectinload(IncidentMitreMapping.technique)
        )
        .order_by(desc(Incident.created_at))
    )

    if status_filter:
        query = query.where(Incident.status == status_filter.upper())
    if severity_filter:
        query = query.where(Incident.severity == severity_filter.upper())
    if min_risk is not None:
        query = query.where(Incident.risk_score >= min_risk)

    result = await db.execute(query.offset(offset).limit(limit))
    incidents = result.scalars().all()

    # Total count query
    count_result = await db.execute(select(Incident))
    total_count = len(count_result.scalars().all())

    items = []
    for inc in incidents:
        tech_summaries = [
            MitreTechniqueSummary(
                technique_id=m.technique_id,
                technique_name=m.technique.technique_name if m.technique else m.technique_id,
                tactic=m.tactic,
                confidence=m.confidence
            )
            for m in inc.mitre_mappings
        ]
        items.append(
            IncidentResponse(
                incident_id=inc.incident_id,
                incident_title=inc.incident_title,
                status=inc.status,
                severity=inc.severity,
                risk_score=inc.risk_score,
                anomaly_score=inc.anomaly_score,
                threat_severity_score=inc.threat_severity_score,
                asset_criticality_score=inc.asset_criticality_score,
                identity_sensitivity_score=inc.identity_sensitivity_score,
                event_sequence_score=inc.event_sequence_score,
                attack_stage_score=inc.attack_stage_score,
                confidence_score=inc.confidence_score,
                evidence_quality=inc.evidence_quality,
                assigned_analyst=inc.assigned_analyst,
                sla_breach_deadline=inc.sla_breach_deadline,
                created_at=inc.created_at,
                updated_at=inc.updated_at,
                event_count=len(inc.event_mappings),
                mitre_techniques=tech_summaries
            )
        )

    return IncidentListResponse(total=total_count, incidents=items)


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Retrieves an individual security incident."""
    stmt = (
        select(Incident)
        .where(Incident.incident_id == incident_id)
        .options(
            selectinload(Incident.event_mappings),
            selectinload(Incident.mitre_mappings).selectinload(IncidentMitreMapping.technique)
        )
    )
    result = await db.execute(stmt)
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found."
        )

    tech_summaries = [
        MitreTechniqueSummary(
            technique_id=m.technique_id,
            technique_name=m.technique.technique_name if m.technique else m.technique_id,
            tactic=m.tactic,
            confidence=m.confidence
        )
        for m in inc.mitre_mappings
    ]

    return IncidentResponse(
        incident_id=inc.incident_id,
        incident_title=inc.incident_title,
        status=inc.status,
        severity=inc.severity,
        risk_score=inc.risk_score,
        anomaly_score=inc.anomaly_score,
        threat_severity_score=inc.threat_severity_score,
        asset_criticality_score=inc.asset_criticality_score,
        identity_sensitivity_score=inc.identity_sensitivity_score,
        event_sequence_score=inc.event_sequence_score,
        attack_stage_score=inc.attack_stage_score,
        confidence_score=inc.confidence_score,
        evidence_quality=inc.evidence_quality,
        assigned_analyst=inc.assigned_analyst,
        sla_breach_deadline=inc.sla_breach_deadline,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        event_count=len(inc.event_mappings),
        mitre_techniques=tech_summaries
    )


@router.patch("/{incident_id}/status", response_model=IncidentResponse)
async def update_incident_status(
    incident_id: uuid.UUID,
    payload: IncidentStatusUpdateRequest,
    current_user: User = Depends(require_any_role(["Incident Responder", "Security Analyst", "Security Admin"])),
    db: AsyncSession = Depends(get_db)
):
    """Transitions an incident through its lifecycle state machine."""
    norm_status = payload.status.upper()
    if norm_status not in ALLOWED_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{payload.status}'. Allowed: {sorted(list(ALLOWED_STATUSES))}"
        )

    stmt = (
        select(Incident)
        .where(Incident.incident_id == incident_id)
        .options(
            selectinload(Incident.event_mappings),
            selectinload(Incident.mitre_mappings).selectinload(IncidentMitreMapping.technique)
        )
    )
    result = await db.execute(stmt)
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found."
        )

    inc.status = norm_status
    if payload.assigned_analyst:
        inc.assigned_analyst = payload.assigned_analyst
    elif not inc.assigned_analyst:
        inc.assigned_analyst = current_user.username

    await db.commit()
    await db.refresh(inc)

    tech_summaries = [
        MitreTechniqueSummary(
            technique_id=m.technique_id,
            technique_name=m.technique.technique_name if m.technique else m.technique_id,
            tactic=m.tactic,
            confidence=m.confidence
        )
        for m in inc.mitre_mappings
    ]

    return IncidentResponse(
        incident_id=inc.incident_id,
        incident_title=inc.incident_title,
        status=inc.status,
        severity=inc.severity,
        risk_score=inc.risk_score,
        anomaly_score=inc.anomaly_score,
        threat_severity_score=inc.threat_severity_score,
        asset_criticality_score=inc.asset_criticality_score,
        identity_sensitivity_score=inc.identity_sensitivity_score,
        event_sequence_score=inc.event_sequence_score,
        attack_stage_score=inc.attack_stage_score,
        confidence_score=inc.confidence_score,
        evidence_quality=inc.evidence_quality,
        assigned_analyst=inc.assigned_analyst,
        sla_breach_deadline=inc.sla_breach_deadline,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        event_count=len(inc.event_mappings),
        mitre_techniques=tech_summaries
    )


@router.get("/{incident_id}/timeline", response_model=IncidentTimelineResponse)
async def get_incident_timeline(
    incident_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Retrieves chronological event sequence supporting the incident."""
    stmt = (
        select(IncidentEventMapping, SecurityEvent)
        .join(SecurityEvent, IncidentEventMapping.event_id == SecurityEvent.event_id)
        .where(IncidentEventMapping.incident_id == incident_id)
        .order_by(SecurityEvent.timestamp.asc())
    )
    result = await db.execute(stmt)
    rows = result.all()

    is_viewer = any(r.name == "Viewer" for r in current_user.roles) and not any(
        r.name in ["Incident Responder", "Security Analyst", "Security Admin"] for r in current_user.roles
    )

    items = []
    for mapping, ev in rows:
        username = ev.username
        source_ip = ev.source_ip
        if is_viewer:
            if username:
                username = username[0] + "***" if len(username) > 1 else "***"
            if source_ip and "." in source_ip:
                parts = source_ip.split(".")
                source_ip = f"{parts[0]}.{parts[1]}.***.***"

        items.append(
            IncidentTimelineItem(
                event_id=ev.event_id,
                timestamp=ev.timestamp,
                event_type=ev.event_type,
                action=ev.action,
                severity=ev.severity,
                username=username,
                source_ip=source_ip,
                device_name=ev.device_name,
                correlation_reason=mapping.correlation_reason,
                sequence_index=mapping.sequence_index
            )
        )

    return IncidentTimelineResponse(incident_id=incident_id, events=items)


@router.get("/{incident_id}/graph", response_model=IncidentGraphResponse)
async def get_incident_attack_graph(
    incident_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Generates node-edge attack graph structure for React Flow canvas."""
    stmt = (
        select(SecurityEvent)
        .join(IncidentEventMapping, SecurityEvent.event_id == IncidentEventMapping.event_id)
        .where(IncidentEventMapping.incident_id == incident_id)
        .order_by(SecurityEvent.timestamp.asc())
    )
    result = await db.execute(stmt)
    events = result.scalars().all()

    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []
    seen_nodes = set()

    for i, ev in enumerate(events):
        # 1. Attacker IP Node
        if ev.source_ip:
            ip_node_id = f"ip-{ev.source_ip}"
            if ip_node_id not in seen_nodes:
                nodes.append(GraphNode(
                    id=ip_node_id,
                    type="attacker_ip",
                    label=f"IP: {ev.source_ip}",
                    metadata={"source_ip": ev.source_ip}
                ))
                seen_nodes.add(ip_node_id)

        # 2. User Node
        if ev.username:
            user_node_id = f"user-{ev.username}"
            if user_node_id not in seen_nodes:
                nodes.append(GraphNode(
                    id=user_node_id,
                    type="user",
                    label=f"User: {ev.username}",
                    metadata={"username": ev.username}
                ))
                seen_nodes.add(user_node_id)

        # 3. Host / Device Node
        host_id = ev.device_name or ev.device_id or "unknown-host"
        device_node_id = f"host-{host_id}"
        if device_node_id not in seen_nodes:
            nodes.append(GraphNode(
                id=device_node_id,
                type="device",
                label=f"Host: {host_id}",
                metadata={"device_id": ev.device_id}
            ))
            seen_nodes.add(device_node_id)

        # Edge from IP -> User
        if ev.source_ip and ev.username:
            edge_id = f"edge-{ev.source_ip}-{ev.username}-{i}"
            edges.append(GraphEdge(
                id=edge_id,
                source=f"ip-{ev.source_ip}",
                target=f"user-{ev.username}",
                label=ev.action
            ))

        # Edge from User -> Host
        if ev.username and host_id:
            edge_id = f"edge-{ev.username}-{host_id}-{i}"
            edges.append(GraphEdge(
                id=edge_id,
                source=f"user-{ev.username}",
                target=device_node_id,
                label=ev.event_type
            ))

    return IncidentGraphResponse(
        incident_id=incident_id,
        nodes=nodes,
        edges=edges
    )
