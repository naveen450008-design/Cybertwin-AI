import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, DateTime, Uuid, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Incident(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    incident_title: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="NEW", nullable=False, index=True)
    # Lifecycle: NEW -> INVESTIGATING -> CONTAINMENT_RECOMMENDED -> RESPONSE_PENDING -> CONTAINED / RESOLVED / FALSE_POSITIVE -> CLOSED
    severity: Mapped[str] = mapped_column(String(32), default="MEDIUM", nullable=False, index=True)
    # Canonical 6-factor risk components:
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    threat_severity_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    asset_criticality_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    identity_sensitivity_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    event_sequence_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    attack_stage_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Composite detection metrics:
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    evidence_quality: Mapped[str] = mapped_column(String(16), default="MEDIUM", nullable=False)
    assigned_analyst: Mapped[str | None] = mapped_column(String(128), nullable=True)
    sla_breach_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    event_mappings: Mapped[list["IncidentEventMapping"]] = relationship(
        "IncidentEventMapping",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentEventMapping.sequence_index",
        lazy="selectin"
    )
    mitre_mappings: Mapped[list["IncidentMitreMapping"]] = relationship(
        "IncidentMitreMapping",
        back_populates="incident",
        cascade="all, delete-orphan",
        lazy="selectin"
    )


class IncidentEventMapping(Base):
    __tablename__ = "incident_event_mappings"

    mapping_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("security_events.event_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    correlation_reason: Mapped[str] = mapped_column(String(256), nullable=False)
    sequence_index: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="event_mappings")
