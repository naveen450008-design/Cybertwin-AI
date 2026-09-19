import asyncio
import os
import sys
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

# Ensure backend root is in PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.config import settings
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.services.bootstrap import bootstrap_roles_and_admin
from app.services.auth_service import AuthService
from app.schemas.auth import UserRegisterRequest

# Test SQLite in-memory database engine
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

TestingSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Create a fresh in-memory database for each test function."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestingSessionLocal() as session:
        # Seed standard roles and bootstrap admin
        await bootstrap_roles_and_admin(session)
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Create test client with overridden database dependency."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def viewer_auth_headers(db_session: AsyncSession) -> dict:
    """Create a Viewer user and return authorization header."""
    user = await AuthService.register_user(
        db_session,
        UserRegisterRequest(
            username="test_viewer",
            full_name="Test Viewer User",
            password="ViewerPassword123!",
            requested_role="Viewer"
        )
    )
    token_resp = AuthService.create_token_for_user(user)
    return {"Authorization": f"Bearer {token_resp.access_token}"}


@pytest_asyncio.fixture(scope="function")
async def admin_auth_headers(db_session: AsyncSession) -> dict:
    """Authenticate the bootstrap Security Admin and return authorization header."""
    admin = await AuthService.authenticate_user(
        db_session,
        username=settings.BOOTSTRAP_ADMIN_USERNAME,
        password=settings.BOOTSTRAP_ADMIN_PASSWORD
    )
    token_resp = AuthService.create_token_for_user(admin)
    return {"Authorization": f"Bearer {token_resp.access_token}"}
