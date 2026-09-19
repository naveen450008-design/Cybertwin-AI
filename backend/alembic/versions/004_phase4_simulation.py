"""004 Phase 4 Safe Response Simulation and Digital Twin Actions

Revision ID: 004_phase4_simulation
Revises: 003_phase3_incidents_mitre
Create Date: 2026-09-19 15:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '004_phase4_simulation'
down_revision: Union[str, None] = '003_phase3_incidents_mitre'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'simulated_response_actions',
        sa.Column('action_id', sa.Uuid(), nullable=False),
        sa.Column('incident_id', sa.Uuid(), nullable=True),
        sa.Column('action_type', sa.String(length=64), nullable=False),
        sa.Column('target_entity_type', sa.String(length=32), nullable=False),
        sa.Column('target_entity_id', sa.String(length=128), nullable=False),
        sa.Column('response_mode', sa.String(length=32), nullable=False, server_default='RECOMMEND'),
        sa.Column('approval_status', sa.String(length=32), nullable=False, server_default='PENDING_APPROVAL'),
        sa.Column('approved_by', sa.String(length=128), nullable=True),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('blast_radius_impact', sa.JSON(), nullable=False),
        sa.Column('is_reverted', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('executed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.incident_id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('action_id')
    )
    op.create_index(op.f('ix_simulated_response_actions_incident_id'), 'simulated_response_actions', ['incident_id'], unique=False)
    op.create_index(op.f('ix_simulated_response_actions_approval_status'), 'simulated_response_actions', ['approval_status'], unique=False)


def downgrade() -> None:
    op.drop_table('simulated_response_actions')
