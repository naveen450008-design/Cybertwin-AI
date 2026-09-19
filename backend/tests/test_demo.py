import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_demo_generate_normal(client: AsyncClient, admin_auth_headers: dict):
    response = await client.post(
        "/api/v1/demo/generate-normal",
        json={"event_count": 50, "seed": 42},
        headers=admin_auth_headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert data["dataset_marker"] == "SYNTHETIC DATA"
    assert data["total_events_created"] == 50


@pytest.mark.asyncio
async def test_demo_generate_suspicious(client: AsyncClient, admin_auth_headers: dict):
    response = await client.post(
        "/api/v1/demo/generate-suspicious",
        json={"scenario_type": "IMPOSSIBLE_TRAVEL", "target_username": "user_02"},
        headers=admin_auth_headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert "IMPOSSIBLE_TRAVEL" in data["scenarios_injected"]


@pytest.mark.asyncio
async def test_demo_run_full_simulation_and_reset(client: AsyncClient, admin_auth_headers: dict):
    # Run simulation
    sim_res = await client.post("/api/v1/demo/run-full-simulation", headers=admin_auth_headers)
    assert sim_res.status_code == 200
    sim_data = sim_res.json()
    assert sim_data["status"] == "COMPLETED"
    assert sim_data["total_events_created"] >= 500

    # Query events to confirm storage
    events_res = await client.get("/api/v1/events?limit=10", headers=admin_auth_headers)
    assert events_res.status_code == 200
    assert events_res.json()["total"] >= 500

    # Reset
    reset_res = await client.post("/api/v1/demo/reset", headers=admin_auth_headers)
    assert reset_res.status_code == 200

    # Confirm purged
    after_res = await client.get("/api/v1/events", headers=admin_auth_headers)
    assert after_res.json()["total"] == 0
