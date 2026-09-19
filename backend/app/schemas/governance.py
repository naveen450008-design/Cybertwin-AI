from pydantic import BaseModel, ConfigDict
from typing import Optional, Dict, Any
from datetime import datetime
import uuid


class AnalystFeedbackRequest(BaseModel):
    incident_id: Optional[uuid.UUID] = None
    verdict: str  # CONFIRMED_THREAT, FALSE_POSITIVE, NEEDS_REVIEW
    confidence_rating: int = 5
    analyst_notes: str = ""


class AnalystFeedbackResponse(BaseModel):
    feedback_id: uuid.UUID
    incident_id: Optional[uuid.UUID] = None
    user_id: Optional[uuid.UUID] = None
    verdict: str
    confidence_rating: int
    analyst_notes: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ModelGovernanceResponse(BaseModel):
    model_name: str
    version: str
    precision: float
    recall: float
    f1_score: float
    drift_score: float
    status: str
    evaluated_at: str
    total_feedback_samples: int
    marker: str = "INTERNAL EVALUATION METRIC"
