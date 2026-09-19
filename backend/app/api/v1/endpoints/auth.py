from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_admin
from app.models.user import User
from app.schemas.auth import (
    UserRegisterRequest,
    UserLoginRequest,
    TokenResponse,
    UserResponse,
    RoleResponse,
)
from app.services.auth_service import AuthService

router = APIRouter()


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new user account",
    description="Creates a new user profile, hashes password with bcrypt, and binds requested role (defaults to Viewer)."
)
async def register(
    payload: UserRegisterRequest,
    db: AsyncSession = Depends(get_db)
) -> Any:
    try:
        user = await AuthService.register_user(db, payload)
        return UserResponse(
            id=user.id,
            username=user.username,
            full_name=user.full_name,
            is_active=user.is_active,
            roles=[RoleResponse(id=r.id, name=r.name, description=r.description) for r in user.roles],
            created_at=user.created_at
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and obtain JWT access token",
    description="Authenticates credentials and returns signed JWT access token with 60-minute expiry."
)
async def login(
    payload: UserLoginRequest,
    db: AsyncSession = Depends(get_db)
) -> Any:
    user = await AuthService.authenticate_user(
        db,
        username=payload.username,
        password=payload.password
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return AuthService.create_token_for_user(user)


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Retrieve current user profile",
    description="Returns the authenticated user details, effective RBAC roles, and creation timestamp."
)
async def read_current_user(
    current_user: User = Depends(get_current_user)
) -> Any:
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        full_name=current_user.full_name,
        is_active=current_user.is_active,
        roles=[RoleResponse(id=r.id, name=r.name, description=r.description) for r in current_user.roles],
        created_at=current_user.created_at
    )


@router.get(
    "/admin-only-action",
    summary="Admin privileged checkpoint",
    description="Test endpoint strictly guarded by Security Admin role to verify RBAC denial."
)
async def admin_only_action(
    current_user: User = Depends(require_admin)
) -> Any:
    return {
        "status": "SUCCESS",
        "message": "Authorized for Security Admin operations.",
        "admin_username": current_user.username
    }
