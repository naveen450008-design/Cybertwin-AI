from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.security import verify_password, get_password_hash, create_access_token
from app.models.user import User, Role, UserRole
from app.schemas.auth import UserRegisterRequest, TokenResponse, UserResponse, RoleResponse


class AuthService:
    @staticmethod
    async def get_user_by_username(db: AsyncSession, username: str) -> Optional[User]:
        """Fetch user by username with roles loaded."""
        result = await db.execute(
            select(User)
            .options(selectinload(User.roles))
            .where(User.username == username)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_role_by_name(db: AsyncSession, role_name: str) -> Optional[Role]:
        """Fetch role entity by name."""
        result = await db.execute(select(Role).where(Role.name == role_name))
        return result.scalar_one_or_none()

    @staticmethod
    async def authenticate_user(
        db: AsyncSession,
        username: str,
        password: str
    ) -> Optional[User]:
        """Verify user credentials against stored bcrypt hash."""
        user = await AuthService.get_user_by_username(db, username)
        if not user or not user.is_active:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user

    @staticmethod
    async def register_user(
        db: AsyncSession,
        payload: UserRegisterRequest
    ) -> User:
        """Register a new user, hash password with bcrypt, and assign role."""
        # Verify username uniqueness
        existing = await AuthService.get_user_by_username(db, payload.username)
        if existing:
            raise ValueError(f"Username '{payload.username}' is already registered")

        # Determine target role
        target_role_name = payload.requested_role or "Viewer"
        role = await AuthService.get_role_by_name(db, target_role_name)
        if not role:
            # Fallback to Viewer if requested role doesn't exist
            role = await AuthService.get_role_by_name(db, "Viewer")
            if not role:
                role = Role(name="Viewer", description="Read-only access")
                db.add(role)
                await db.flush()

        hashed_pwd = get_password_hash(payload.password)
        new_user = User(
            username=payload.username,
            full_name=payload.full_name,
            hashed_password=hashed_pwd,
            is_active=True
        )
        db.add(new_user)
        await db.flush()

        user_role = UserRole(user_id=new_user.id, role_id=role.id)
        db.add(user_role)
        await db.commit()

        # Reload with relationships
        user = await AuthService.get_user_by_username(db, new_user.username)
        return user

    @staticmethod
    def create_token_for_user(user: User) -> TokenResponse:
        """Issue signed JWT bearer access token."""
        roles = user.role_names
        access_token = create_access_token(
            subject=user.username,
            roles=roles,
            user_id=str(user.id)
        )
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=UserResponse(
                id=user.id,
                username=user.username,
                full_name=user.full_name,
                is_active=user.is_active,
                roles=[RoleResponse(id=r.id, name=r.name, description=r.description) for r in user.roles],
                created_at=user.created_at
            )
        )
