import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.ueba import UEBABaseline

logger = logging.getLogger("cyber_soc.ueba")


class UEBAService:
    """Manages 30-day statistical behavioral baselines for users and devices."""

    @staticmethod
    async def get_baseline(
        db: AsyncSession,
        entity_type: str,
        entity_id: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch baseline record for user or device."""
        stmt = select(UEBABaseline).where(
            UEBABaseline.entity_type == entity_type,
            UEBABaseline.entity_id == entity_id
        )
        result = await db.execute(stmt)
        record = result.scalar_one_or_none()
        if not record:
            return None

        return {
            "entity_type": record.entity_type,
            "entity_id": record.entity_id,
            "active_hours_histogram": record.active_hours_histogram,
            "known_devices": record.known_devices,
            "typical_locations": record.typical_locations,
            "common_processes": record.common_processes,
            "mean_transfer_volume": record.mean_transfer_volume,
            "stddev_transfer_volume": record.stddev_transfer_volume,
            "mean_connection_frequency": record.mean_connection_frequency,
            "sample_count": record.sample_count,
            "last_updated": record.last_updated
        }

    @staticmethod
    async def update_baseline_with_event(
        db: AsyncSession,
        event: Dict[str, Any]
    ) -> None:
        """Update user and device baseline distributions with a verified normal event."""
        username = event.get("username")
        device_id = event.get("device_id")
        ts: datetime = event.get("timestamp") or datetime.now(timezone.utc)
        location = event.get("location")
        proc_name = event.get("process_name")
        data_volume = event.get("data_volume") or 0

        # 1. Update user baseline
        if username:
            stmt = select(UEBABaseline).where(
                UEBABaseline.entity_type == "USER",
                UEBABaseline.entity_id == username
            )
            res = await db.execute(stmt)
            user_baseline = res.scalar_one_or_none()

            if not user_baseline:
                user_baseline = UEBABaseline(
                    entity_type="USER",
                    entity_id=username,
                    active_hours_histogram={str(h): 0 for h in range(24)},
                    known_devices=[device_id] if device_id else [],
                    typical_locations=[location] if location else [],
                    common_processes=[proc_name] if proc_name else [],
                    mean_transfer_volume=float(data_volume),
                    stddev_transfer_volume=float(data_volume * 0.2),
                    sample_count=1,
                    last_updated=ts
                )
                db.add(user_baseline)
            else:
                # Update histogram
                hour_key = str(ts.hour)
                hist = dict(user_baseline.active_hours_histogram)
                hist[hour_key] = hist.get(hour_key, 0) + 1
                user_baseline.active_hours_histogram = hist

                # Update devices
                if device_id and device_id not in user_baseline.known_devices:
                    user_baseline.known_devices = list(user_baseline.known_devices) + [device_id]

                # Update locations
                if location and location not in user_baseline.typical_locations:
                    user_baseline.typical_locations = list(user_baseline.typical_locations) + [location]

                # Update processes
                if proc_name and proc_name not in user_baseline.common_processes:
                    user_baseline.common_processes = list(user_baseline.common_processes) + [proc_name]

                # Update data transfer running statistics
                if data_volume > 0:
                    n = user_baseline.sample_count + 1
                    old_mean = user_baseline.mean_transfer_volume
                    new_mean = old_mean + (data_volume - old_mean) / n
                    user_baseline.mean_transfer_volume = new_mean
                    user_baseline.sample_count = n

                user_baseline.last_updated = ts

        # 2. Update device baseline
        if device_id:
            stmt = select(UEBABaseline).where(
                UEBABaseline.entity_type == "DEVICE",
                UEBABaseline.entity_id == device_id
            )
            res = await db.execute(stmt)
            device_baseline = res.scalar_one_or_none()

            if not device_baseline:
                device_baseline = UEBABaseline(
                    entity_type="DEVICE",
                    entity_id=device_id,
                    active_hours_histogram={str(h): 0 for h in range(24)},
                    known_devices=[device_id],
                    typical_locations=[location] if location else [],
                    common_processes=[proc_name] if proc_name else [],
                    mean_transfer_volume=float(data_volume),
                    stddev_transfer_volume=float(data_volume * 0.2),
                    sample_count=1,
                    last_updated=ts
                )
                db.add(device_baseline)
            else:
                if proc_name and proc_name not in device_baseline.common_processes:
                    device_baseline.common_processes = list(device_baseline.common_processes) + [proc_name]
                device_baseline.sample_count += 1
                device_baseline.last_updated = ts

        await db.flush()
