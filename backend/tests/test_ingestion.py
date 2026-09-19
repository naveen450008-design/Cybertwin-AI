import pytest
from datetime import datetime, timezone
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_rest_api_event_ingestion(client: AsyncClient, admin_auth_headers: dict):
    now_iso = datetime.now(timezone.utc).isoformat()
    events = [
        {
            "timestamp": now_iso,
            "username": "alice.smith",
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.1.10",
            "device_id": "DEV-WKS-001",
            "event_type": "AUTHENTICATION",
            "action": "USER_LOGIN",
            "status": "SUCCESS",
            "severity": "INFORMATIONAL",
            "process_name": "winlogon.exe",
            "data_volume": 0,
            "location": "New York, USA",
            "authentication_method": "MFA",
            "metadata": {"session_id": "sess_123"}
        }
    ]

    response = await client.post("/api/v1/events/ingest", json=events, headers=admin_auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total_received"] == 1
    assert data["valid_events"] == 1
    assert data["stored_events"] == 1
    assert data["duplicate_events"] == 0
    assert data["dataset_marker"] == "SYNTHETIC DATA"

    # Ingest duplicate event - duplicate count should be 1
    dup_res = await client.post("/api/v1/events/ingest", json=events, headers=admin_auth_headers)
    assert dup_res.status_code == 200
    dup_data = dup_res.json()
    assert dup_data["duplicate_events"] == 1
    assert dup_data["stored_events"] == 0


@pytest.mark.asyncio
async def test_csv_upload_ingestion(client: AsyncClient, admin_auth_headers: dict):
    csv_data = """timestamp,username,source_ip,destination_ip,device_id,event_type,action,status,severity,process_name,data_volume,location
2026-09-19T08:00:00Z,bob.jones,192.168.1.55,10.0.2.10,DEV-WKS-002,AUTHENTICATION,USER_LOGIN,SUCCESS,LOW,winlogon.exe,0,"London, UK"
2026-09-19T08:05:00Z,bob.jones,192.168.1.55,10.0.2.10,DEV-WKS-002,PROCESS_EXECUTION,PROCESS_SPAWN,SUCCESS,INFORMATIONAL,chrome.exe,0,"London, UK"
"""
    files = {"file": ("test_events.csv", csv_data.encode("utf-8"), "text/csv")}
    response = await client.post("/api/v1/events/upload-csv", files=files, headers=admin_auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total_received"] == 2
    assert data["valid_events"] == 2
    assert data["stored_events"] == 2


@pytest.mark.asyncio
async def test_json_upload_ingestion(client: AsyncClient, admin_auth_headers: dict):
    json_data = """[
        {
            "timestamp": "2026-09-19T09:00:00Z",
            "username": "carol.white",
            "source_ip": "192.168.1.60",
            "event_type": "AUTHENTICATION",
            "action": "USER_LOGIN",
            "status": "SUCCESS",
            "severity": "INFORMATIONAL",
            "authentication_method": "PASSWORD"
        }
    ]"""
    files = {"file": ("test_events.json", json_data.encode("utf-8"), "application/json")}
    response = await client.post("/api/v1/events/upload-json", files=files, headers=admin_auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total_received"] == 1
    assert data["valid_events"] == 1
    assert data["stored_events"] == 1


@pytest.mark.asyncio
async def test_viewer_pii_masking(client: AsyncClient, admin_auth_headers: dict, viewer_auth_headers: dict):
    # Ingest an event with sensitive IP and username
    event = [
        {
            "timestamp": "2026-09-19T10:00:00Z",
            "username": "sensitive.target",
            "source_ip": "192.168.10.99",
            "destination_ip": "10.0.0.50",
            "event_type": "AUTHENTICATION",
            "action": "USER_LOGIN",
            "status": "SUCCESS",
            "severity": "INFORMATIONAL"
        }
    ]
    await client.post("/api/v1/events/ingest", json=event, headers=admin_auth_headers)

    # 1. Query as Viewer: IP and username must be masked
    viewer_res = await client.get("/api/v1/events", headers=viewer_auth_headers)
    assert viewer_res.status_code == 200
    v_items = viewer_res.json()["items"]
    found_viewer_ev = next(e for e in v_items if e["event_type"] == "AUTHENTICATION")
    assert found_viewer_ev["source_ip"] == "192.168.***.***"
    assert found_viewer_ev["username"].startswith("s***")

    # 2. Query as Admin: Cleartext visible
    admin_res = await client.get("/api/v1/events", headers=admin_auth_headers)
    assert admin_res.status_code == 200
    a_items = admin_res.json()["items"]
    found_admin_ev = next(e for e in a_items if e["event_type"] == "AUTHENTICATION")
    assert found_admin_ev["source_ip"] == "192.168.10.99"
    assert found_admin_ev["username"] == "sensitive.target"
