import pytest
from httpx import AsyncClient

from app.core.config import settings


@pytest.mark.asyncio
async def test_bootstrap_admin_login_success(client: AsyncClient):
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "username": settings.BOOTSTRAP_ADMIN_USERNAME,
            "password": settings.BOOTSTRAP_ADMIN_PASSWORD
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == settings.BOOTSTRAP_ADMIN_USERNAME
    roles = [r["name"] for r in data["user"]["roles"]]
    assert "Security Admin" in roles


@pytest.mark.asyncio
async def test_login_failure_wrong_password(client: AsyncClient):
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "username": settings.BOOTSTRAP_ADMIN_USERNAME,
            "password": "IncorrectPassword123!"
        }
    )
    assert response.status_code == 401
    assert "Incorrect username or password" in response.json()["detail"]


@pytest.mark.asyncio
async def test_login_failure_nonexistent_user(client: AsyncClient):
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "username": "ghost_user_does_not_exist",
            "password": "AnyPassword123!"
        }
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_user_registration_success(client: AsyncClient):
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "username": "soc_analyst_bob",
            "full_name": "Bob Analyst",
            "password": "SecurePassword123!",
            "requested_role": "Security Analyst"
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "soc_analyst_bob"
    roles = [r["name"] for r in data["roles"]]
    assert "Security Analyst" in roles


@pytest.mark.asyncio
async def test_user_registration_duplicate_username_fails(client: AsyncClient):
    payload = {
        "username": "duplicate_candidate",
        "full_name": "Duplicate User",
        "password": "Password123!",
        "requested_role": "Viewer"
    }
    res1 = await client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == 201

    res2 = await client.post("/api/v1/auth/register", json=payload)
    assert res2.status_code == 400
    assert "already registered" in res2.json()["detail"]


@pytest.mark.asyncio
async def test_get_current_user_me_success(client: AsyncClient, admin_auth_headers: dict):
    response = await client.get("/api/v1/auth/me", headers=admin_auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == settings.BOOTSTRAP_ADMIN_USERNAME


@pytest.mark.asyncio
async def test_get_current_user_me_unauthorized(client: AsyncClient):
    # No header
    res1 = await client.get("/api/v1/auth/me")
    assert res1.status_code == 401

    # Invalid bearer token
    res2 = await client.get("/api/v1/auth/me", headers={"Authorization": "Bearer invalid_token"})
    assert res2.status_code == 401
