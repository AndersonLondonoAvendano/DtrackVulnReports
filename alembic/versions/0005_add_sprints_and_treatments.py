"""Add sprints, vulnerability_treatments, treatment_status_history

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-07

Iteracion 3: flujo de tratamiento de vulnerabilidades por sprints.
Migracion puramente aditiva -- no toca datos existentes (remediation_plans/
remediation_tasks quedan intactos, sprint_id nullable en remediation_plans).
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Fuente única de verdad: vulntrack.domain.services.treatment_transitions.ACTIVE_TREATMENT_STATES
_ACTIVE_STATES_SQL = "'DESCARTADA','EN_CURSO','FINALIZADA','PENDIENTE','POSPUESTA'"


def upgrade() -> None:
    op.create_table(
        "sprints",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("nombre", sa.String(255), nullable=False),
        sa.Column("anio", sa.Integer, nullable=False),
        sa.Column("trimestre", sa.Integer, nullable=False),
        sa.Column("fecha_inicio", sa.Date, nullable=False),
        sa.Column("fecha_fin", sa.Date, nullable=False),
        sa.Column("estado", sa.String(20), nullable=False, server_default="PLANEADO"),
        sa.Column("external_id", sa.String(100), nullable=True),
        sa.Column("origen", sa.String(20), nullable=False, server_default="MANUAL"),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "fecha_fin > fecha_inicio", name="ck_sprints_fecha_fin_after_inicio"
        ),
    )
    op.create_index("ix_sprints_anio_trimestre", "sprints", ["anio", "trimestre"])

    with op.batch_alter_table("remediation_plans") as batch_op:
        batch_op.add_column(sa.Column("sprint_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_remediation_plans_sprint_id", "sprints", ["sprint_id"], ["id"]
        )

    op.create_table(
        "vulnerability_treatments",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "project_uuid",
            sa.String(36),
            sa.ForeignKey("projects.uuid", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("vuln_key", sa.String(100), nullable=False),
        sa.Column("cve_id", sa.String(30), nullable=True),
        sa.Column(
            "finding_id", sa.Integer, sa.ForeignKey("findings.id", ondelete="SET NULL")
        ),
        sa.Column(
            "plan_id",
            sa.Integer,
            sa.ForeignKey("remediation_plans.id", ondelete="SET NULL"),
        ),
        sa.Column("sprint_id", sa.Integer, sa.ForeignKey("sprints.id"), nullable=False),
        sa.Column("responsable", sa.String(255), nullable=True),
        sa.Column("estado", sa.String(20), nullable=False, server_default="PENDIENTE"),
        sa.Column("priority_band", sa.String(20), nullable=False),
        sa.Column(
            "fecha_creacion", sa.DateTime, nullable=False, server_default=sa.func.now()
        ),
        sa.Column("fecha_objetivo", sa.Date, nullable=True),
        sa.Column("fecha_cierre", sa.DateTime, nullable=True),
        sa.Column("notas", sa.Text, nullable=True),
        sa.Column("motivo", sa.Text, nullable=True),
        sa.Column("recurrence_flag", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("recurrence_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_recurrence_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "uq_treatment_active_project_vuln",
        "vulnerability_treatments",
        ["project_uuid", "vuln_key"],
        unique=True,
        sqlite_where=sa.text(f"estado IN ({_ACTIVE_STATES_SQL})"),
        postgresql_where=sa.text(f"estado IN ({_ACTIVE_STATES_SQL})"),
    )
    op.create_index(
        "ix_treatments_project_estado",
        "vulnerability_treatments",
        ["project_uuid", "estado"],
    )
    op.create_index("ix_treatments_sprint", "vulnerability_treatments", ["sprint_id"])
    op.create_index("ix_treatments_vuln_key", "vulnerability_treatments", ["vuln_key"])

    op.create_table(
        "treatment_status_history",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "treatment_id",
            sa.Integer,
            sa.ForeignKey("vulnerability_treatments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("from_status", sa.String(20), nullable=True),
        sa.Column("to_status", sa.String(20), nullable=False),
        sa.Column("sprint_id", sa.Integer, sa.ForeignKey("sprints.id"), nullable=False),
        sa.Column("changed_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("note", sa.Text, nullable=True),
    )
    op.create_index(
        "ix_treatment_history_treatment", "treatment_status_history", ["treatment_id"]
    )
    op.create_index(
        "ix_treatment_history_sprint", "treatment_status_history", ["sprint_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_treatment_history_sprint", table_name="treatment_status_history")
    op.drop_index("ix_treatment_history_treatment", table_name="treatment_status_history")
    op.drop_table("treatment_status_history")

    op.drop_index("ix_treatments_vuln_key", table_name="vulnerability_treatments")
    op.drop_index("ix_treatments_sprint", table_name="vulnerability_treatments")
    op.drop_index("ix_treatments_project_estado", table_name="vulnerability_treatments")
    op.drop_index(
        "uq_treatment_active_project_vuln", table_name="vulnerability_treatments"
    )
    op.drop_table("vulnerability_treatments")

    with op.batch_alter_table("remediation_plans") as batch_op:
        batch_op.drop_constraint("fk_remediation_plans_sprint_id", type_="foreignkey")
        batch_op.drop_column("sprint_id")

    op.drop_index("ix_sprints_anio_trimestre", table_name="sprints")
    op.drop_table("sprints")
