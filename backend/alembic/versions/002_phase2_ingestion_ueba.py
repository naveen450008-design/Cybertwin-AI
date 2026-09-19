"""002 Phase 2 Ingestion and UEBA Baselines

Revision ID: 002_phase2_ingestion_ueba
Revises: 001_initial_phase1
Create Date: 2026-09-19 13:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '002_phase2_ingestion_ueba'
down_revision: Union[str, None] = '001_initial_phase1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create ingestion_batches table
    op.create_table(
        'ingestion_batches',
        sa.Column('batch_id', sa.Uuid(), nullable=False),
        sa.Column('source_type', sa.String(length=64), nullable=False),
        sa.Column('filename', sa.String(length=256), nullable=True),
        sa.Column('total_received', sa.Integer(), nullable=False, default=0),
        sa.Column('valid_events', sa.Integer(), nullable=False, default=0),
        sa.Column('invalid_events', sa.Integer(), nullable=False, default=0),
        sa.Column('duplicate_events', sa.Integer(), nullable=False, default=0),
        sa.Column('stored_events', sa.Integer(), nullable=False, default=0),
        sa.Column('processing_status', sa.String(length=32), nullable=False, default='PROCESSING'),
        sa.Column('error_summary', sa.JSON(), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('batch_id')
    )
    op.create_index(op.f('ix_ingestion_batches_started_at'), 'ingestion_batches', ['started_at'], unique=False)

    # 2. Create ueba_baselines table
    op.create_table(
        'ueba_baselines',
        sa.Column('baseline_id', sa.Uuid(), nullable=False),
        sa.Column('entity_type', sa.String(length=32), nullable=False),
        sa.Column('entity_id', sa.String(length=128), nullable=False),
        sa.Column('active_hours_histogram', sa.JSON(), nullable=False),
        sa.Column('known_devices', sa.JSON(), nullable=False),
        sa.Column('typical_locations', sa.JSON(), nullable=False),
        sa.Column('common_processes', sa.JSON(), nullable=False),
        sa.Column('mean_transfer_volume', sa.Float(), nullable=False, default=0.0),
        sa.Column('stddev_transfer_volume', sa.Float(), nullable=False, default=0.0),
        sa.Column('mean_connection_frequency', sa.Float(), nullable=False, default=0.0),
        sa.Column('observation_window_days', sa.Integer(), nullable=False, default=30),
        sa.Column('sample_count', sa.Integer(), nullable=False, default=0),
        sa.Column('last_updated', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('baseline_id'),
        sa.UniqueConstraint('entity_type', 'entity_id', name='uq_entity_baseline')
    )
    op.create_index(op.f('ix_ueba_baselines_entity_id'), 'ueba_baselines', ['entity_id'], unique=False)


def downgrade() -> None:
    op.drop_table('ueba_baselines')
    op.drop_table('ingestion_batches')
