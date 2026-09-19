import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, Uuid, JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class IngestionBatch(Base):
    __tablename__ = "ingestion_batches"

    batch_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)  # 'CSV_UPLOAD', 'JSON_UPLOAD', 'REST_API', 'SYNTHETIC_GENERATOR'
    filename: Mapped[str | None] = mapped_column(String(256), nullable=True)
    total_received: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    valid_events: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    invalid_events: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duplicate_events: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    stored_events: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    processing_status: Mapped[str] = mapped_column(String(32), default="PROCESSING", nullable=False)  # 'PROCESSING', 'COMPLETED', 'FAILED'
    error_summary: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
