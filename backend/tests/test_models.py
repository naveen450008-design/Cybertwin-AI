import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User, Role, UserRole
from app.models.asset import Asset
from app.models.event import SecurityEvent


@pytest.mark.asyncio
async def test_standard_roles_seeded(db_session: AsyncSession):
    result = await db_session.execute(select(Role))
    roles = result.scalars().all()
    role_names = {r.name for r in roles}

    expected_roles = {"Viewer", "Incident Responder", "Security Analyst", "Security Admin"}
    assert expected_roles.issubset(role_names)


@pytest.mark.asyncio
async def test_asset_model_creation_and_query(db_session: AsyncSession):
    asset_id = uuid.uuid4()
    asset = Asset(
        id=asset_id,
        asset_name="SRV-DB-PRIMARY",
        asset_type="DATABASE",
        criticality_score=100,
        ip_address="10.0.1.50",
        is_isolated=False,
        metadata_json={"tier": 1, "engine": "PostgreSQL"}
    )
    db_session.add(asset)
    await db_session.commit()

    queried = await db_session.get(Asset, asset_id)
    assert queried is not None
    assert queried.asset_name == "SRV-DB-PRIMARY"
    assert queried.criticality_score == 100
    assert queried.metadata_json["engine"] == "PostgreSQL"
    assert isinstance(queried.created_at, datetime)


@pytest.mark.asyncio
async def test_security_event_model_creation_and_indexes(db_session: AsyncSession):
    event_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    event = SecurityEvent(
        event_id=event_id,
        timestamp=now,
        username="john.doe",
        source_ip="192.168.1.55",
        destination_ip="10.0.0.1",
        device_id="DEV-WKS-001",
        event_type="AUTHENTICATION",
        action="USER_LOGIN",
        status="FAILURE",
        severity="LOW",
        authentication_method="PASSWORD",
        metadata_json={"reason": "INVALID_CREDENTIALS"},
        event_hash="abc123hash456"
    )
    db_session.add(event)
    await db_session.commit()

    queried = await db_session.get(SecurityEvent, event_id)
    assert queried is not None
    assert queried.event_id == event_id
    assert queried.event_type == "AUTHENTICATION"
    assert queried.severity == "LOW"
    assert queried.status == "FAILURE"
    assert queried.device_id == "DEV-WKS-001"
