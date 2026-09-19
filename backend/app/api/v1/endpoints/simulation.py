import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.user import User
from app.models.simulation import SimulatedResponseAction
from app.api.deps import get_current_user, require_any_role, require_role
from app.services.digital_twin_service import DigitalTwinService
from app.services.blast_radius_service import BlastRadiusService
from app.services.audit_service import AuditService
from app.schemas.simulation import (
    BlastRadiusRequest,
    BlastRadiusResponse,
    SimulationActionCreateRequest,
    SimulationActionResponse,
    TopologyResponse
)

router = APIRouter()


@router.get("/topology", response_model=TopologyResponse)
async def get_digital_twin_topology(
    current_user: User = Depends(get_current_user)
):
    """Retrieves in-memory Digital Twin graph topology for SOC visualization."""
    twin = DigitalTwinService.get_instance()
    snapshot = twin.get_topology_snapshot()
    return TopologyResponse(
        nodes=snapshot["nodes"],
        edges=snapshot["edges"],
        marker="SIMULATED ACTION",
        safety_invariant="Zero OS / Network Mutability"
    )


@router.post("/blast-radius", response_model=BlastRadiusResponse)
async def calculate_blast_radius(
    payload: BlastRadiusRequest,
    current_user: User = Depends(get_current_user)
):
    """Calculates operational disruption score before executing a simulated response."""
    report = BlastRadiusService.calculate_blast_radius(
        action_type=payload.action_type,
        target_entity_id=payload.target_entity_id
    )
    return BlastRadiusResponse(
        action_type=payload.action_type,
        target_entity_id=payload.target_entity_id,
        disruption_score=report.disruption_score,
        severed_sessions_count=report.severed_sessions_count,
        collateral_users_count=report.collateral_users_count,
        tier1_disrupted=report.tier1_disrupted,
        estimated_risk_reduction_pct=report.estimated_risk_reduction_pct,
        recommended_mode=report.recommended_mode,
        impact_tier=report.impact_tier,
        summary=report.summary,
        marker="SIMULATED ACTION"
    )


@router.post("/actions/request", response_model=SimulationActionResponse)
async def stage_simulated_action(
    payload: SimulationActionCreateRequest,
    current_user: User = Depends(require_any_role(["Incident Responder", "Security Analyst", "Security Admin"])),
    db: AsyncSession = Depends(get_db)
):
    """Stages a simulated response action with blast-radius calculation."""
    report = BlastRadiusService.calculate_blast_radius(
        action_type=payload.action_type,
        target_entity_id=payload.target_entity_id
    )

    action_id = uuid.uuid4()
    blast_json = {
        "disruption_score": report.disruption_score,
        "severed_sessions_count": report.severed_sessions_count,
        "collateral_users_count": report.collateral_users_count,
        "tier1_disrupted": report.tier1_disrupted,
        "estimated_risk_reduction_pct": report.estimated_risk_reduction_pct,
        "impact_tier": report.impact_tier,
        "summary": report.summary
    }

    sim_action = SimulatedResponseAction(
        action_id=action_id,
        incident_id=payload.incident_id,
        action_type=payload.action_type,
        target_entity_type=payload.target_entity_type.upper(),
        target_entity_id=payload.target_entity_id,
        response_mode=payload.response_mode.upper(),
        approval_status="PENDING_APPROVAL",
        blast_radius_impact=blast_json,
        is_reverted=False
    )
    db.add(sim_action)
    await db.commit()
    await db.refresh(sim_action)

    return sim_action


@router.post("/actions/{action_id}/approve", response_model=SimulationActionResponse)
async def approve_and_execute_simulation(
    action_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Approves and executes a simulated response action strictly in the Digital Twin."""
    stmt = select(SimulatedResponseAction).where(SimulatedResponseAction.action_id == action_id)
    result = await db.execute(stmt)
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Simulation action '{action_id}' not found."
        )

    # RBAC Enforcement: High-impact actions require Security Analyst or Security Admin
    is_high_impact = action.action_type in ["SIMULATE_ISOLATE_DEVICE", "SIMULATE_BLOCK_IP"]
    user_roles = [r.name for r in current_user.roles]
    if is_high_impact and not any(r in ["Security Analyst", "Security Admin"] for r in user_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="High-impact simulated actions require 'Security Analyst' or 'Security Admin' approval."
        )

    # Execute simulation in Digital Twin
    twin = DigitalTwinService.get_instance()
    sim_result = twin.execute_simulation(
        action_id=str(action.action_id),
        action_type=action.action_type,
        target_entity_id=action.target_entity_id
    )

    action.approval_status = "EXECUTED_SIMULATION"
    action.approved_by = current_user.username
    action.approved_at = datetime.now(timezone.utc)
    action.executed_at = datetime.now(timezone.utc)
    action.blast_radius_impact["execution_result"] = sim_result

    await db.commit()
    await db.refresh(action)

    # Record in cryptographic audit ledger
    try:
        user_role = current_user.roles[0].name if current_user.roles else "Security Analyst"
        await AuditService.record_mutation(
            db=db,
            actor_username=current_user.username,
            actor_role=user_role,
            action_taken=f"EXECUTE_{action.action_type}",
            target_entity_type=action.target_entity_type,
            target_entity_id=action.target_entity_id,
            old_state={"approval_status": "PENDING_APPROVAL"},
            new_state={"approval_status": "EXECUTED_SIMULATION", "approved_by": current_user.username},
            session_metadata={"action_id": str(action.action_id)}
        )
    except Exception as audit_err:
        pass

    return action


@router.post("/actions/{action_id}/rollback", response_model=SimulationActionResponse)
async def rollback_simulated_action(
    action_id: uuid.UUID,
    current_user: User = Depends(require_any_role(["Incident Responder", "Security Analyst", "Security Admin"])),
    db: AsyncSession = Depends(get_db)
):
    """Rolls back an executed simulated response action in the Digital Twin."""
    stmt = select(SimulatedResponseAction).where(SimulatedResponseAction.action_id == action_id)
    result = await db.execute(stmt)
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Simulation action '{action_id}' not found."
        )

    twin = DigitalTwinService.get_instance()
    twin.rollback_simulation(str(action.action_id))

    action.approval_status = "ROLLED_BACK"
    action.is_reverted = True
    await db.commit()
    await db.refresh(action)

    # Record rollback in audit ledger
    try:
        user_role = current_user.roles[0].name if current_user.roles else "Security Analyst"
        await AuditService.record_mutation(
            db=db,
            actor_username=current_user.username,
            actor_role=user_role,
            action_taken=f"ROLLBACK_{action.action_type}",
            target_entity_type=action.target_entity_type,
            target_entity_id=action.target_entity_id,
            old_state={"approval_status": "EXECUTED_SIMULATION"},
            new_state={"approval_status": "ROLLED_BACK", "is_reverted": True},
            session_metadata={"action_id": str(action.action_id)}
        )
    except Exception as audit_err:
        pass

    return action


@router.get("/actions", response_model=List[SimulationActionResponse])
async def list_simulated_actions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Lists recent simulated response actions."""
    stmt = select(SimulatedResponseAction).order_by(desc(SimulatedResponseAction.created_at)).limit(50)
    result = await db.execute(stmt)
    return result.scalars().all()
