import csv
import io
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.event import SecurityEvent
from app.models.ingestion import IngestionBatch
from app.schemas.event import EventCreateRequest, EventBatchIngestResponse
from app.services.synthetic_service import SyntheticDataService
from app.services.detection_rules import DetectionRuleEngine
from app.services.ueba_service import UEBAService
from app.services.ml_anomaly_service import MLAnomalyService
from app.services.correlation_service import CorrelationService

logger = logging.getLogger("cyber_soc.ingestion")

FORBIDDEN_CREDENTIAL_KEYS = {
    "password", "token", "auth_token", "access_token",
    "private_key", "secret_key", "secret", "api_key"
}


class IngestionService:
    """Multi-channel security event ingestion, deduplication, and anomaly evaluation service."""

    @staticmethod
    def sanitize_metadata(meta: Dict[str, Any]) -> Dict[str, Any]:
        """Strip forbidden credentials from metadata."""
        if not meta or not isinstance(meta, dict):
            return {}
        sanitized = {}
        for k, v in meta.items():
            if k.lower() not in FORBIDDEN_CREDENTIAL_KEYS:
                sanitized[k] = v
        return sanitized

    @staticmethod
    async def process_event_batch(
        db: AsyncSession,
        raw_events: List[Dict[str, Any]],
        source_type: str,
        filename: str = None
    ) -> EventBatchIngestResponse:
        """Process, validate, deduplicate, and persist a batch of security events."""
        batch_id = uuid.uuid4()
        total_received = len(raw_events)
        valid_events = 0
        invalid_events = 0
        duplicate_events = 0
        stored_events = 0
        alerts_generated = 0
        errors = []

        # Initialize tracking record
        batch_record = IngestionBatch(
            batch_id=batch_id,
            source_type=source_type,
            filename=filename,
            total_received=total_received,
            processing_status="PROCESSING"
        )
        db.add(batch_record)
        await db.flush()

        # Query recent events for sliding-window detection
        recent_res = await db.execute(
            select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(100)
        )
        recent_entities = [
            {
                "timestamp": ev.timestamp.replace(tzinfo=timezone.utc) if (ev.timestamp and ev.timestamp.tzinfo is None) else ev.timestamp,
                "username": ev.username,
                "source_ip": ev.source_ip,
                "destination_ip": ev.destination_ip,
                "event_type": ev.event_type,
                "status": ev.status,
                "severity": ev.severity,
                "process_name": ev.process_name,
                "data_volume": ev.data_volume,
                "location": ev.location,
            }
            for ev in recent_res.scalars().all()
        ]

        events_to_persist: List[SecurityEvent] = []

        for idx, raw in enumerate(raw_events):
            try:
                # Pydantic validation
                validated = EventCreateRequest(**raw)
                valid_events += 1

                # Canonical event hash
                ehash = SyntheticDataService.compute_event_hash(
                    validated.timestamp,
                    validated.username,
                    validated.source_ip,
                    validated.destination_ip,
                    validated.event_type,
                    validated.action
                )

                # Check duplicate
                dup_check = await db.execute(
                    select(SecurityEvent.event_id).where(SecurityEvent.event_hash == ehash)
                )
                if dup_check.scalar_one_or_none():
                    duplicate_events += 1
                    continue

                clean_meta = IngestionService.sanitize_metadata(validated.metadata or {})

                # Fetch baseline if user present
                ueba_baseline = None
                if validated.username:
                    ueba_baseline = await UEBAService.get_baseline(db, "USER", validated.username)

                # Detection rules evaluation
                event_dict = {
                    "timestamp": validated.timestamp,
                    "username": validated.username,
                    "source_ip": validated.source_ip,
                    "destination_ip": validated.destination_ip,
                    "device_id": validated.device_id,
                    "event_type": validated.event_type,
                    "action": validated.action,
                    "status": validated.status,
                    "severity": validated.severity,
                    "process_name": validated.process_name,
                    "data_volume": validated.data_volume,
                    "location": validated.location,
                }
                triggered_rules = DetectionRuleEngine.evaluate_all(event_dict, recent_entities, ueba_baseline)
                if triggered_rules:
                    alerts_generated += len(triggered_rules)
                    clean_meta["triggered_rules"] = triggered_rules

                # ML Anomaly evaluation
                anomaly_telemetry = MLAnomalyService.evaluate_anomaly(event_dict, recent_entities, ueba_baseline)
                clean_meta["ml_anomaly"] = anomaly_telemetry

                # Escalate severity if critical rules triggered
                effective_severity = validated.severity
                for r in triggered_rules:
                    if r["severity"] == "CRITICAL":
                        effective_severity = "CRITICAL"
                        break
                    elif r["severity"] == "HIGH" and effective_severity in ["INFORMATIONAL", "LOW", "MEDIUM"]:
                        effective_severity = "HIGH"

                sec_event = SecurityEvent(
                    timestamp=validated.timestamp,
                    username=validated.username,
                    user_id=validated.user_id,
                    source_ip=validated.source_ip,
                    destination_ip=validated.destination_ip,
                    device_id=validated.device_id,
                    device_name=validated.device_name,
                    server_id=validated.server_id,
                    event_type=validated.event_type,
                    action=validated.action,
                    status=validated.status,
                    severity=effective_severity,
                    process_name=validated.process_name,
                    data_volume=validated.data_volume,
                    location=validated.location,
                    authentication_method=validated.authentication_method or "NONE",
                    metadata_json=clean_meta,
                    event_hash=ehash
                )
                events_to_persist.append(sec_event)
                recent_entities.insert(0, event_dict)
                stored_events += 1

            except Exception as e:
                invalid_events += 1
                errors.append({"index": idx, "error": str(e)})

        if events_to_persist:
            db.add_all(events_to_persist)
            await db.flush()
            # Correlate events into incidents
            for ev in events_to_persist:
                try:
                    await CorrelationService.correlate_event(db, ev)
                except Exception as corr_err:
                    logger.warning(f"Correlation skipped for event {ev.event_id}: {corr_err}")

        # Update batch completion
        batch_record.valid_events = valid_events
        batch_record.invalid_events = invalid_events
        batch_record.duplicate_events = duplicate_events
        batch_record.stored_events = stored_events
        batch_record.processing_status = "COMPLETED" if not errors else "COMPLETED_WITH_ERRORS"
        batch_record.error_summary = {"errors": errors[:50]}  # cap error report
        batch_record.completed_at = datetime.now(timezone.utc)

        await db.commit()

        return EventBatchIngestResponse(
            batch_id=batch_id,
            total_received=total_received,
            valid_events=valid_events,
            invalid_events=invalid_events,
            duplicate_events=duplicate_events,
            stored_events=stored_events,
            processing_status=batch_record.processing_status,
            alerts_generated=alerts_generated,
            dataset_marker="SYNTHETIC DATA"
        )

    @staticmethod
    async def parse_csv_stream(
        db: AsyncSession,
        csv_content: str,
        filename: str
    ) -> EventBatchIngestResponse:
        """Parse raw CSV string with automatic header matching."""
        reader = csv.DictReader(io.StringIO(csv_content))
        raw_events = []

        for row in reader:
            # Map headers and strip whitespace
            clean_row = {k.strip(): (v.strip() if v else None) for k, v in row.items() if k}
            
            # Normalize timestamp
            ts_str = clean_row.get("timestamp")
            if ts_str:
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except ValueError:
                    ts = datetime.now(timezone.utc)
            else:
                ts = datetime.now(timezone.utc)

            event_dict = {
                "timestamp": ts,
                "username": clean_row.get("username"),
                "source_ip": clean_row.get("source_ip"),
                "destination_ip": clean_row.get("destination_ip"),
                "device_id": clean_row.get("device_id"),
                "device_name": clean_row.get("device_name"),
                "server_id": clean_row.get("server_id"),
                "event_type": clean_row.get("event_type", "AUTHENTICATION"),
                "action": clean_row.get("action", "UNKNOWN_ACTION"),
                "status": clean_row.get("status", "SUCCESS"),
                "severity": clean_row.get("severity", "INFORMATIONAL"),
                "process_name": clean_row.get("process_name"),
                "data_volume": int(clean_row["data_volume"]) if clean_row.get("data_volume") and clean_row["data_volume"].isdigit() else None,
                "location": clean_row.get("location"),
                "authentication_method": clean_row.get("authentication_method", "NONE"),
                "metadata": {}
            }
            raw_events.append(event_dict)

        return await IngestionService.process_event_batch(db, raw_events, "CSV_UPLOAD", filename)

    @staticmethod
    async def parse_json_stream(
        db: AsyncSession,
        json_content: str,
        filename: str
    ) -> EventBatchIngestResponse:
        """Parse JSON array of events."""
        data = json.loads(json_content)
        if isinstance(data, dict):
            raw_events = [data]
        elif isinstance(data, list):
            raw_events = data
        else:
            raise ValueError("JSON must contain an object or an array of event objects")

        return await IngestionService.process_event_batch(db, raw_events, "JSON_UPLOAD", filename)
