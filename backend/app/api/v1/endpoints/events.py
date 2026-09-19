import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.api.deps import get_db, get_current_user, require_analyst
from app.models.user import User
from app.models.event import SecurityEvent
from app.models.ingestion import IngestionBatch
from app.schemas.event import (
    EventCreateRequest,
    EventResponse,
    EventBatchIngestResponse,
    EventListResponse,
)
from app.services.ingestion_service import IngestionService

router = APIRouter()


def mask_pii_for_viewer(event_dict: dict, user_roles: List[str]) -> dict:
    """Mask IP addresses and usernames if the requester is solely a Viewer."""
    if "Viewer" in user_roles and len(user_roles) == 1:
        # Mask IP
        src_ip = event_dict.get("source_ip")
        if src_ip and "." in src_ip:
            parts = src_ip.split(".")
            if len(parts) == 4:
                event_dict["source_ip"] = f"{parts[0]}.{parts[1]}.***.***"

        dst_ip = event_dict.get("destination_ip")
        if dst_ip and "." in dst_ip:
            parts = dst_ip.split(".")
            if len(parts) == 4:
                event_dict["destination_ip"] = f"{parts[0]}.{parts[1]}.***.***"

        # Mask username
        uname = event_dict.get("username")
        if uname and len(uname) > 2:
            event_dict["username"] = uname[0] + "***"

    return event_dict


@router.post(
    "/ingest",
    response_model=EventBatchIngestResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest batch of security events via REST API",
    description="Ingest, validate, deduplicate, and score security events. Requires Security Analyst or Admin role."
)
async def ingest_events(
    events: List[EventCreateRequest],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    raw_dicts = [e.model_dump() for e in events]
    return await IngestionService.process_event_batch(db, raw_dicts, "REST_API")


@router.post(
    "/upload-csv",
    response_model=EventBatchIngestResponse,
    summary="Upload security events CSV file",
    description="Streamed CSV upload with schema mapping and deduplication."
)
async def upload_csv_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    content = await file.read()
    try:
        csv_str = content.decode("utf-8")
    except UnicodeDecodeError:
        csv_str = content.decode("latin-1")

    return await IngestionService.parse_csv_stream(db, csv_str, file.filename or "upload.csv")


@router.post(
    "/upload-json",
    response_model=EventBatchIngestResponse,
    summary="Upload security events JSON batch file",
    description="Bulk upload of JSON array of events."
)
async def upload_json_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    content = await file.read()
    try:
        json_str = content.decode("utf-8")
    except UnicodeDecodeError:
        json_str = content.decode("latin-1")

    try:
        return await IngestionService.parse_json_stream(db, json_str, file.filename or "upload.json")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "",
    response_model=EventListResponse,
    summary="Query canonical security events",
    description="Returns paginated security events. Automatically applies PII masking for Viewers."
)
async def list_events(
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    stmt = select(SecurityEvent)

    if start_time:
        stmt = stmt.where(SecurityEvent.timestamp >= start_time)
    if end_time:
        stmt = stmt.where(SecurityEvent.timestamp <= end_time)
    if event_type:
        stmt = stmt.where(SecurityEvent.event_type == event_type.upper())
    if severity:
        stmt = stmt.where(SecurityEvent.severity == severity.upper())
    if username:
        stmt = stmt.where(SecurityEvent.username == username)

    # Count total
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Fetch page
    stmt = stmt.order_by(SecurityEvent.timestamp.desc()).limit(limit).offset(offset)
    results = (await db.execute(stmt)).scalars().all()

    user_roles = current_user.role_names
    items = []
    for ev in results:
        ev_dict = {
            "event_id": ev.event_id,
            "timestamp": ev.timestamp,
            "username": ev.username,
            "user_id": ev.user_id,
            "source_ip": ev.source_ip,
            "destination_ip": ev.destination_ip,
            "device_id": ev.device_id,
            "device_name": ev.device_name,
            "server_id": ev.server_id,
            "event_type": ev.event_type,
            "action": ev.action,
            "status": ev.status,
            "severity": ev.severity,
            "process_name": ev.process_name,
            "data_volume": ev.data_volume,
            "location": ev.location,
            "authentication_method": ev.authentication_method,
            "metadata_json": ev.metadata_json,
            "event_hash": ev.event_hash,
            "created_at": ev.created_at,
        }
        masked = mask_pii_for_viewer(ev_dict, user_roles)
        items.append(EventResponse(**masked))

    return EventListResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=items
    )


@router.get(
    "/batches",
    summary="List ingestion batches",
    description="Retrieve telemetry records for all file and API ingestion batches."
)
async def list_batches(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    stmt = select(IngestionBatch).order_by(IngestionBatch.started_at.desc()).limit(limit).offset(offset)
    res = await db.execute(stmt)
    return res.scalars().all()
