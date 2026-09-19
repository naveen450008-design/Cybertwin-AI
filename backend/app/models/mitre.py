import uuid
from sqlalchemy import String, Float, Text, JSON, Uuid, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    technique_id: Mapped[str] = mapped_column(String(32), primary_key=True)  # e.g., 'T1110.001'
    technique_name: Mapped[str] = mapped_column(String(128), nullable=False)
    tactics: Mapped[list] = mapped_column(JSON, default=list, nullable=False)  # e.g., ['Credential Access']
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)


class IncidentMitreMapping(Base):
    __tablename__ = "incident_mitre_mappings"

    mapping_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    technique_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("mitre_techniques.technique_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    tactic: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_event_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid,
        ForeignKey("security_events.event_id", ondelete="SET NULL"),
        nullable=True
    )
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)

    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="mitre_mappings")
    technique: Mapped["MitreTechnique"] = relationship("MitreTechnique", lazy="selectin")
