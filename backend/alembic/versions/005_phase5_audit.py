"""005 Phase 5 Tamper-Evident Hash-Chained Audit Ledger

Revision ID: 005_phase5_audit
Revises: 004_phase4_simulation
Create Date: 2026-09-19 16:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '005_phase5_audit'
down_revision: Union[str, None] = '004_phase4_simulation'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'audit_ledger',
        sa.Column('ledger_index', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
        sa.Column('audit_id', sa.Uuid(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('actor_username', sa.String(length=128), nullable=False),
        sa.Column('actor_role', sa.String(length=64), nullable=False),
        sa.Column('action_taken', sa.String(length=64), nullable=False),
        sa.Column('target_entity_type', sa.String(length=64), nullable=False),
        sa.Column('target_entity_id', sa.String(length=128), nullable=False),
        sa.Column('old_state_json', sa.JSON(), nullable=False),
        sa.Column('new_state_json', sa.JSON(), nullable=False),
        sa.Column('session_metadata', sa.JSON(), nullable=False),
        sa.Column('previous_hash', sa.String(length=64), nullable=False),
        sa.Column('current_hash', sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint('ledger_index'),
        sa.UniqueConstraint('current_hash')
    )
    op.create_index(op.f('ix_audit_ledger_audit_id'), 'audit_ledger', ['audit_id'], unique=True)
    op.create_index(op.f('ix_audit_ledger_timestamp'), 'audit_ledger', ['timestamp'], unique=False)


def downgrade() -> None:
    op.drop_table('audit_ledger')
