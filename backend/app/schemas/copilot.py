from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import uuid


class CopilotQueryRequest(BaseModel):
    incident_id: uuid.UUID
    question: Optional[str] = None


class CopilotQueryResponse(BaseModel):
    incident_id: str
    query: str
    executive_summary: str
    verified_facts: List[Dict[str, Any]]
    mitre_techniques: List[Dict[str, Any]]
    estimated_predictions: List[Dict[str, Any]]
    recommended_simulated_action: str
    compliance_tags: List[str]
    model_provenance: str

    # Generative AI Security Copilot Sections
    incident_summary: Optional[Dict[str, Any]] = None
    why_suspicious: Optional[Dict[str, Any]] = None
    attack_story: Optional[Dict[str, Any]] = None
    evidence_explanation: Optional[Dict[str, Any]] = None
    mitre_explanation: Optional[Dict[str, Any]] = None
    risk_explanation: Optional[Dict[str, Any]] = None
    estimated_prediction: Optional[Dict[str, Any]] = None
    ai_recommendation: Optional[Dict[str, Any]] = None
    similar_incidents: Optional[Dict[str, Any]] = None
    prompt_injection_defense: Optional[Dict[str, Any]] = None


class SimilarIncidentResponse(BaseModel):
    incident_id: str
    title: str
    status: str
    severity: str
    risk_score: float
    similarity_score: float
    created_at: str
    marker: str = "ESTIMATED PREDICTION"
