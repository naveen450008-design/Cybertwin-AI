from typing import Optional, Any, Dict
from pydantic import BaseModel


class ProblemDetail(BaseModel):
    """RFC 7807 compliant problem details for HTTP APIs."""
    type: str = "about:blank"
    title: str
    status: int
    detail: str
    instance: Optional[str] = None
    errors: Optional[Any] = None
