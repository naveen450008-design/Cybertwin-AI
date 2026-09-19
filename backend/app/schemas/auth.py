import uuid
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict


class RoleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: Optional[str] = None


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    full_name: str
    is_active: bool
    roles: List[RoleResponse]
    created_at: datetime


class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, description="Unique username")
    full_name: str = Field(..., min_length=2, max_length=128, description="Full display name")
    password: str = Field(..., min_length=8, max_length=128, description="Password (minimum 8 characters)")
    requested_role: Optional[str] = Field(
        default="Viewer",
        description="Requested role: Viewer, Incident Responder, Security Analyst, Security Admin"
    )


class UserLoginRequest(BaseModel):
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse
