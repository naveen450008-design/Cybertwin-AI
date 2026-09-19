from typing import List, Callable
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.user import User
from app.services.auth_service import AuthService

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Validate bearer token and resolve authenticated User entity."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception

    username: str = payload.get("sub")
    if username is None:
        raise credentials_exception

    user = await AuthService.get_user_by_username(db, username=username)
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )
    return user


def require_role(required_role: str) -> Callable:
    """Dependency factory checking that the current user has the exact specified role."""
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        user_roles = current_user.role_names
        if required_role not in user_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires role '{required_role}'. Current roles: {user_roles}"
            )
        return current_user
    return role_checker


def require_any_role(allowed_roles: List[str]) -> Callable:
    """Dependency factory checking that the current user has at least one of the allowed roles."""
    async def roles_checker(current_user: User = Depends(get_current_user)) -> User:
        user_roles = set(current_user.role_names)
        if not user_roles.intersection(allowed_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Requires one of {allowed_roles}. Current roles: {list(user_roles)}"
            )
        return current_user
    return roles_checker


# Convenient role dependencies matching the 4-tier matrix
require_admin = require_role("Security Admin")
require_analyst = require_any_role(["Security Analyst", "Security Admin"])
require_responder = require_any_role(["Incident Responder", "Security Analyst", "Security Admin"])
require_viewer = require_any_role(["Viewer", "Incident Responder", "Security Analyst", "Security Admin"])
