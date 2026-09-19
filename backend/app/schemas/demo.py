from typing import List, Optional
from pydantic import BaseModel, Field


class DemoGenerateRequest(BaseModel):
    event_count: int = Field(default=200, ge=10, le=2000)
    seed: int = Field(default=42, description="Deterministic pseudo-random seed")


class DemoScenarioRequest(BaseModel):
    scenario_type: str = Field(
        ...,
        description="BRUTE_FORCE | IMPOSSIBLE_TRAVEL | SUSPICIOUS_PROCESS | LATERAL_MOVEMENT | DATA_EXFILTRATION"
    )
    target_username: Optional[str] = Field(default=None)


class DemoResponse(BaseModel):
    status: str
    dataset_marker: str = "SYNTHETIC DATA"
    total_events_created: int
    scenarios_injected: List[str]
    message: str
