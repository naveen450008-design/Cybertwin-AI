from datetime import datetime, timezone
from typing import Any, Optional


def ensure_utc(dt: Any) -> Optional[datetime]:
    """Ensure datetime object is timezone-aware and in UTC."""
    if dt is None:
        return None
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except Exception:
            return None
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def diff_seconds(dt1: Any, dt2: Any) -> Optional[float]:
    """Compute difference in seconds between two datetimes (dt1 - dt2) safely,
    normalizing timezone awareness differences between naive and aware datetimes.
    """
    u1 = ensure_utc(dt1)
    u2 = ensure_utc(dt2)
    if u1 is None or u2 is None:
        return None
    return (u1 - u2).total_seconds()
