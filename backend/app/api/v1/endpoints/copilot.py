import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.user import User
from app.api.deps import get_current_user
from app.services.copilot_service import CopilotService
from app.services.similar_incident_service import SimilarIncidentService
from app.schemas.copilot import (
    CopilotQueryRequest,
    CopilotQueryResponse,
    SimilarIncidentResponse
)

router = APIRouter()


@router.post("/query", response_model=CopilotQueryResponse)
async def query_investigation_copilot(
    payload: CopilotQueryRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Answers investigation queries grounded strictly in database facts and evidence."""
    report = await CopilotService.investigate_incident(
        db=db,
        incident_id=payload.incident_id,
        question=payload.question
    )
    if "error" in report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=report["error"]
        )
    return CopilotQueryResponse(**report)


@router.get("/similar/{incident_id}", response_model=List[SimilarIncidentResponse])
async def get_similar_incidents(
    incident_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Finds historically similar incidents using cosine vector similarity."""
    similar = await SimilarIncidentService.find_similar_incidents(
        db=db,
        target_incident_id=incident_id
    )
    return [SimilarIncidentResponse(**s) for s in similar]
