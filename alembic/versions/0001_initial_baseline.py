"""Baseline inicial — sin tablas todavía (se agregan en 0002_create_tables)

Revision ID: 0001
Revises:
Create Date: 2026-06-23

"""
from __future__ import annotations

from typing import Sequence, Union

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
