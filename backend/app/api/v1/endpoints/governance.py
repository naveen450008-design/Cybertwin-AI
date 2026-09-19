from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.user import User
from app.models.governance import AnalystFeedback
from app.api.deps import get_current_user, require_any_role, require_role
from app.services.governance_service import GovernanceService
from app.schemas.governance import (
    AnalystFeedbackRequest,
    AnalystFeedbackResponse,
    ModelGovernanceResponse
)

router = APIRouter()


@router.post("/feedback", response_model=AnalystFeedbackResponse)
async def submit_analyst_feedback(
    payload: AnalystFeedbackRequest,
    current_user: User = Depends(require_any_role(["Incident Responder", "Security Analyst", "Security Admin"])),
    db: AsyncSession = Depends(get_db)
):
    """Submits analyst ground truth verdict for incident evaluation and model calibration."""
    feedback = await GovernanceService.record_feedback(
        db=db,
        incident_id=payload.incident_id,
        user_id=current_user.id,
        verdict=payload.verdict,
        confidence_rating=payload.confidence_rating,
        analyst_notes=payload.analyst_notes
    )
    return feedback


@router.get("/metrics", response_model=ModelGovernanceResponse)
async def get_model_metrics(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Retrieves empirical Precision, Recall, F1 and drift metrics calculated from ground-truth feedback."""
    metrics = await GovernanceService.compute_metrics(db)
    return ModelGovernanceResponse(**metrics)
