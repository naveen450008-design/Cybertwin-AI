"""006 Phase 6 Analyst Feedback and Model Governance

Revision ID: 006_phase6_governance
Revises: 005_phase5_audit
Create Date: 2026-09-19 17:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '006_phase6_governance'
down_revision: Union[str, None] = '005_phase5_audit'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create analyst_feedback table
    op.create_table(
        'analyst_feedback',
        sa.Column('feedback_id', sa.Uuid(), nullable=False),
        sa.Column('incident_id', sa.Uuid(), nullable=True),
        sa.Column('user_id', sa.Uuid(), nullable=True),
        sa.Column('verdict', sa.String(length=32), nullable=False),
        sa.Column('confidence_rating', sa.Integer(), nullable=False, server_default='5'),
        sa.Column('analyst_notes', sa.Text(), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.incident_id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('feedback_id')
    )
    op.create_index(op.f('ix_analyst_feedback_incident_id'), 'analyst_feedback', ['incident_id'], unique=False)

    # 2. Create model_governance table
    op.create_table(
        'model_governance',
        sa.Column('model_id', sa.Uuid(), nullable=False),
        sa.Column('model_name', sa.String(length=64), nullable=False),
        sa.Column('version', sa.String(length=32), nullable=False),
        sa.Column('precision', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('recall', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('f1_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('drift_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='ACTIVE'),
        sa.Column('certified_by', sa.String(length=128), nullable=True),
        sa.Column('evaluated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('model_id')
    )


def downgrade() -> None:
    op.drop_table('model_governance')
    op.drop_table('analyst_feedback')
