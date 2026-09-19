import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, Text, DateTime, Uuid, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    feedback_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid,
        ForeignKey("incidents.incident_id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True
    )
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    # Verdicts: CONFIRMED_THREAT, FALSE_POSITIVE, NEEDS_REVIEW
    confidence_rating: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    # 1 to 5 scale
    analyst_notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )


class ModelGovernance(Base):
    __tablename__ = "model_governance"

    model_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    model_name: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    precision: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    recall: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    f1_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    drift_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE", nullable=False)
    # Status: ACTIVE, CANDIDATE, DEPRECATED
    certified_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
