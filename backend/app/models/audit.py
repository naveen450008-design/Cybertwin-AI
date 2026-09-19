import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, Uuid, JSON, BigInteger
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditLedger(Base):
    __tablename__ = "audit_ledger"

    ledger_index: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    audit_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4, nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )
    actor_username: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(64), nullable=False)
    action_taken: Mapped[str] = mapped_column(String(64), nullable=False)
    target_entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_entity_id: Mapped[str] = mapped_column(String(128), nullable=False)
    old_state_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    new_state_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    session_metadata: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    current_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
