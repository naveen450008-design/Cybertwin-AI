"""003 Phase 3 Incidents and MITRE ATT&CK

Revision ID: 003_phase3_incidents_mitre
Revises: 002_phase2_ingestion_ueba
Create Date: 2026-09-19 14:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '003_phase3_incidents_mitre'
down_revision: Union[str, None] = '002_phase2_ingestion_ueba'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create incidents table
    op.create_table(
        'incidents',
        sa.Column('incident_id', sa.Uuid(), nullable=False),
        sa.Column('incident_title', sa.String(length=256), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='NEW'),
        sa.Column('severity', sa.String(length=32), nullable=False, server_default='MEDIUM'),
        sa.Column('risk_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('anomaly_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('threat_severity_score', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('asset_criticality_score', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('identity_sensitivity_score', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('event_sequence_score', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('attack_stage_score', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('confidence_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('evidence_quality', sa.String(length=16), nullable=False, server_default='MEDIUM'),
        sa.Column('assigned_analyst', sa.String(length=128), nullable=True),
        sa.Column('sla_breach_deadline', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('incident_id')
    )
    op.create_index(op.f('ix_incidents_status'), 'incidents', ['status'], unique=False)
    op.create_index(op.f('ix_incidents_severity'), 'incidents', ['severity'], unique=False)
    op.create_index(op.f('ix_incidents_risk_score'), 'incidents', ['risk_score'], unique=False)
    op.create_index(op.f('ix_incidents_created_at'), 'incidents', ['created_at'], unique=False)

    # 2. Create mitre_techniques table
    op.create_table(
        'mitre_techniques',
        sa.Column('technique_id', sa.String(length=32), nullable=False),
        sa.Column('technique_name', sa.String(length=128), nullable=False),
        sa.Column('tactics', sa.JSON(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint('technique_id')
    )

    # 3. Create incident_event_mappings table
    op.create_table(
        'incident_event_mappings',
        sa.Column('mapping_id', sa.Uuid(), nullable=False),
        sa.Column('incident_id', sa.Uuid(), nullable=False),
        sa.Column('event_id', sa.Uuid(), nullable=False),
        sa.Column('correlation_reason', sa.String(length=256), nullable=False),
        sa.Column('sequence_index', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('added_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.incident_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['event_id'], ['security_events.event_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('mapping_id')
    )
    op.create_index(op.f('ix_incident_event_mappings_incident_id'), 'incident_event_mappings', ['incident_id'], unique=False)
    op.create_index(op.f('ix_incident_event_mappings_event_id'), 'incident_event_mappings', ['event_id'], unique=False)

    # 4. Create incident_mitre_mappings table
    op.create_table(
        'incident_mitre_mappings',
        sa.Column('mapping_id', sa.Uuid(), nullable=False),
        sa.Column('incident_id', sa.Uuid(), nullable=False),
        sa.Column('technique_id', sa.String(length=32), nullable=False),
        sa.Column('tactic', sa.String(length=64), nullable=False),
        sa.Column('evidence_event_id', sa.Uuid(), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.incident_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['technique_id'], ['mitre_techniques.technique_id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['evidence_event_id'], ['security_events.event_id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('mapping_id')
    )
    op.create_index(op.f('ix_incident_mitre_mappings_incident_id'), 'incident_mitre_mappings', ['incident_id'], unique=False)
    op.create_index(op.f('ix_incident_mitre_mappings_technique_id'), 'incident_mitre_mappings', ['technique_id'], unique=False)


def downgrade() -> None:
    op.drop_table('incident_mitre_mappings')
    op.drop_table('incident_event_mappings')
    op.drop_table('mitre_techniques')
    op.drop_table('incidents')
