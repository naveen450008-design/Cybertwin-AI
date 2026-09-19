import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_admin_can_access_admin_only_endpoint(client: AsyncClient, admin_auth_headers: dict):
    response = await client.get("/api/v1/auth/admin-only-action", headers=admin_auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert "Authorized for Security Admin operations" in data["message"]


@pytest.mark.asyncio
async def test_viewer_denied_from_admin_only_endpoint(client: AsyncClient, viewer_auth_headers: dict):
    """
    CRITICAL ACCEPTANCE TEST:
    Viewer must NOT be allowed to access Security Admin-only functionality.
    Must receive HTTP 403 Forbidden.
    """
    response = await client.get("/api/v1/auth/admin-only-action", headers=viewer_auth_headers)
    assert response.status_code == 403
    data = response.json()
    assert "Security Admin" in data["detail"]


@pytest.mark.asyncio
async def test_unauthenticated_request_denied_with_401(client: AsyncClient):
    response = await client.get("/api/v1/auth/admin-only-action")
    assert response.status_code == 401
