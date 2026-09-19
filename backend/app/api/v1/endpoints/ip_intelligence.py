from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user, require_viewer
from app.models.user import User
from app.schemas.ip_intelligence import (
    IPIntelligenceSummary,
    IPIntelligenceDetail,
    ThreatRadarResponse,
    SecurityHealthScoreResponse,
)
from app.services.ip_intelligence_service import IPIntelligenceService

router = APIRouter()


@router.get(
    "/summary",
    response_model=List[IPIntelligenceSummary],
    summary="List observed IP intelligence profiles",
    description="Returns aggregated passive IP intelligence profiles for all distinct IPs observed in security telemetry."
)
async def get_observed_ips_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer)
):
    return await IPIntelligenceService.get_all_observed_ips_summary(db, current_user)


@router.get(
    "/details/{ip_address}",
    response_model=IPIntelligenceDetail,
    summary="Get passive IP threat intelligence profile",
    description="Retrieves RFC classification, evidence-grounded risk score, behavioural history, entity graph, and attack path."
)
async def get_ip_deep_intelligence(
    ip_address: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer)
):
    detail = await IPIntelligenceService.get_ip_deep_intelligence(db, ip_address, current_user)
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP address '{ip_address}' not found in telemetry records."
        )
    return detail


@router.get(
    "/threat-radar",
    response_model=ThreatRadarResponse,
    summary="Get Threat Radar entities and polar coordinates",
    description="Computes polar coordinates for currently observed security entities (IPs, Incidents, Users, Hosts)."
)
async def get_threat_radar(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer)
):
    return await IPIntelligenceService.get_threat_radar_entities(db, current_user)


@router.get(
    "/security-score",
    response_model=SecurityHealthScoreResponse,
    summary="Get tenant-wide Security Health Score",
    description="Computes transparent composite tenant posture score based on active incidents, anomalies, and containment rate."
)
async def get_security_health_score(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer)
):
    return await IPIntelligenceService.get_tenant_security_health_score(db, current_user)
