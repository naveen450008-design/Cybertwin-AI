import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Boolean, DateTime, Uuid, JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    asset_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # 'WORKSTATION', 'SERVER', 'GATEWAY', 'DATABASE'
    criticality_score: Mapped[int] = mapped_column(Integer, default=40, nullable=False)  # 40 standard, 75 tier-2, 100 tier-1
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True, index=True)
    mac_address: Mapped[str] = mapped_column(String(32), nullable=True)
    is_isolated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    owner_username: Mapped[str] = mapped_column(String(128), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )
