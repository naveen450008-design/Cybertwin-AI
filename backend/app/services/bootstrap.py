import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.core.security import get_password_hash
from app.models.user import Role, User, UserRole

logger = logging.getLogger("cyber_soc.bootstrap")

STANDARD_ROLES = [
    ("Viewer", "Read-only access with PII masking for observational review"),
    ("Incident Responder", "Triage access with authority to approve low-impact simulations"),
    ("Security Analyst", "Full investigation, feedback, and high-impact simulation approval"),
    ("Security Admin", "Full system governance, model deployment, and user management"),
]


async def bootstrap_roles_and_admin(db: AsyncSession) -> None:
    """
    Idempotently initialize default RBAC roles and provisions the initial
    Security Admin user from environment configuration if no admin exists.
    """
    # 1. Ensure all standard roles exist
    role_map = {}
    for role_name, description in STANDARD_ROLES:
        result = await db.execute(select(Role).where(Role.name == role_name))
        role = result.scalar_one_or_none()
        if not role:
            role = Role(name=role_name, description=description)
            db.add(role)
            await db.flush()
            logger.info(f"Initialized role: {role_name}")
        role_map[role_name] = role

    # 2. Check if a Security Admin user exists
    admin_role = role_map["Security Admin"]
    admin_query = await db.execute(
        select(User).join(User.roles).where(Role.name == "Security Admin")
    )
    existing_admin = admin_query.scalars().first()

    if not existing_admin:
        # Check if user with bootstrap username exists
        user_query = await db.execute(
            select(User).where(User.username == settings.BOOTSTRAP_ADMIN_USERNAME)
        )
        user = user_query.scalar_one_or_none()

        if not user:
            # Create bootstrap admin
            hashed_pwd = get_password_hash(settings.BOOTSTRAP_ADMIN_PASSWORD)
            user = User(
                username=settings.BOOTSTRAP_ADMIN_USERNAME,
                full_name="Initial Security Administrator",
                hashed_password=hashed_pwd,
                is_active=True
            )
            db.add(user)
            await db.flush()

            # Assign Security Admin role
            user_role = UserRole(user_id=user.id, role_id=admin_role.id)
            db.add(user_role)
            await db.commit()
            logger.info(
                f"Successfully bootstrapped Security Admin user '{settings.BOOTSTRAP_ADMIN_USERNAME}'"
            )
        else:
            # Attach admin role if missing
            if admin_role not in user.roles:
                user_role = UserRole(user_id=user.id, role_id=admin_role.id)
                db.add(user_role)
                await db.commit()
                logger.info(f"Granted Security Admin role to existing user '{user.username}'")
    else:
        logger.info("Security Admin account already provisioned.")
