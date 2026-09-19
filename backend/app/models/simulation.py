import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, DateTime, Uuid, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class SimulatedResponseAction(Base):
    __tablename__ = "simulated_response_actions"

    action_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid,
        ForeignKey("incidents.incident_id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    # Types: SIMULATE_BLOCK_IP, SIMULATE_ISOLATE_DEVICE, SIMULATE_TERMINATE_SESSION, SIMULATE_RESTRICT_ACCESS, FLAG_USER_FOR_MONITORING
    target_entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # Target: IP, DEVICE, USER
    target_entity_id: Mapped[str] = mapped_column(String(128), nullable=False)
    response_mode: Mapped[str] = mapped_column(String(32), default="RECOMMEND", nullable=False)
    # Modes: OBSERVE, RECOMMEND, CONTROLLED_AUTONOMOUS
    approval_status: Mapped[str] = mapped_column(String(32), default="PENDING_APPROVAL", nullable=False, index=True)
    # Status: PENDING_APPROVAL, APPROVED, REJECTED, EXECUTED_SIMULATION, ROLLED_BACK
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    blast_radius_impact: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    is_reverted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
