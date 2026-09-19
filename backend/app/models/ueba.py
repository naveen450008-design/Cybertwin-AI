import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, DateTime, Uuid, JSON, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class UEBABaseline(Base):
    __tablename__ = "ueba_baselines"

    baseline_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)  # 'USER', 'DEVICE'
    entity_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)  # username or device_id
    active_hours_histogram: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)  # {"0": 1, "1": 0, ...}
    known_devices: Mapped[list] = mapped_column(JSON, default=list, nullable=False)  # ["DEV-WKS-001", ...]
    typical_locations: Mapped[list] = mapped_column(JSON, default=list, nullable=False)  # ["New York, USA", ...]
    common_processes: Mapped[list] = mapped_column(JSON, default=list, nullable=False)  # ["explorer.exe", ...]
    mean_transfer_volume: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    stddev_transfer_volume: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    mean_connection_frequency: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    observation_window_days: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_updated: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    __table_args__ = (
        UniqueConstraint("entity_type", "entity_id", name="uq_entity_baseline"),
    )
