from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: datetime
    database: str
    details: Optional[Dict[str, Any]] = None
