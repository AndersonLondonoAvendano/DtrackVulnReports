"""Add cve_id column to findings

Revision ID: 0004
Revises: 0003
Create Date: 2026-06-30
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(sa.Column("cve_id", sa.String(30), nullable=True))
        batch_op.create_index("ix_findings_cve_id", ["cve_id"])


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_index("ix_findings_cve_id")
        batch_op.drop_column("cve_id")
