"""Finding lifecycle + identidad D1 (proyecto+CVE/vulnId+componente+version)

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-09

Iteracion 4: ciclo de vida de findings (ACTIVA/RESUELTA, reincidencia) para
soportar reconciliacion de sync (Bloque B); identidad D1 en
vulnerability_treatments (component_name/component_version) para que la
anti-duplicacion distinga el mismo CVE en dos componentes distintos.

Migracion aditiva sobre datos existentes -- no borra filas. Antes de crear
`uq_findings_identity` se verifica que no existan colisiones bajo la
identidad D1 en `findings`; si las hay, la migracion aborta (no se
resuelven automaticamente duplicados de datos reales).
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Fuente única de verdad: vulntrack.domain.services.treatment_transitions.ACTIVE_TREATMENT_STATES
_ACTIVE_STATES_SQL = "'DESCARTADA','EN_CURSO','FINALIZADA','PENDIENTE','POSPUESTA'"


def upgrade() -> None:
    # ── findings: ciclo de vida ────────────────────────────────────────────
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(
            sa.Column(
                "estado_ciclo_vida",
                sa.String(20),
                nullable=False,
                server_default="ACTIVA",
            )
        )
        batch_op.add_column(sa.Column("primera_deteccion_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("ultima_vista_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("resuelta_at", sa.DateTime(), nullable=True))
        batch_op.add_column(
            sa.Column(
                "es_reincidente", sa.Boolean(), nullable=False, server_default="0"
            )
        )
        batch_op.add_column(
            sa.Column("reaparicion_count", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.add_column(sa.Column("ultima_reaparicion_at", sa.DateTime(), nullable=True))

    op.execute(
        sa.text(
            "UPDATE findings SET primera_deteccion_at = created_at, "
            "ultima_vista_at = last_synced_at "
            "WHERE primera_deteccion_at IS NULL"
        )
    )

    # Verificación de colisiones bajo identidad D1 antes de indexar --
    # aborta la migración en vez de fusionar/borrar datos reales en silencio.
    conn = op.get_bind()
    dupes = conn.execute(
        sa.text(
            "SELECT project_uuid, COALESCE(cve_id, vuln_id) AS vk, component_name, "
            "COALESCE(component_version, '') AS cv, COUNT(*) AS n "
            "FROM findings "
            "GROUP BY project_uuid, vk, component_name, cv "
            "HAVING COUNT(*) > 1"
        )
    ).fetchall()
    if dupes:
        raise RuntimeError(
            "Colisiones de identidad D1 (project_uuid, cve/vuln_id, component_name, "
            f"component_version) encontradas en findings, abortando migración 0006: "
            f"{list(dupes)[:5]}"
        )

    op.create_index(
        "uq_findings_identity",
        "findings",
        [
            sa.text("project_uuid"),
            sa.text("COALESCE(cve_id, vuln_id)"),
            sa.text("component_name"),
            sa.text("COALESCE(component_version, '')"),
        ],
        unique=True,
    )

    # ── vulnerability_treatments: componente/versión + subtipo + flag de plan ──
    with op.batch_alter_table("vulnerability_treatments") as batch_op:
        batch_op.add_column(sa.Column("component_name", sa.String(255), nullable=True))
        batch_op.add_column(sa.Column("component_version", sa.String(100), nullable=True))
        batch_op.add_column(sa.Column("finalizacion_subtipo", sa.String(20), nullable=True))
        batch_op.add_column(
            sa.Column("activo_en_plan", sa.Boolean(), nullable=False, server_default="1")
        )

    op.execute(
        sa.text(
            "UPDATE vulnerability_treatments "
            "SET component_name = (SELECT f.component_name FROM findings f "
            "                      WHERE f.id = vulnerability_treatments.finding_id), "
            "    component_version = (SELECT f.component_version FROM findings f "
            "                         WHERE f.id = vulnerability_treatments.finding_id) "
            "WHERE finding_id IS NOT NULL"
        )
    )

    op.drop_index("uq_treatment_active_project_vuln", table_name="vulnerability_treatments")
    op.create_index(
        "uq_treatment_active_project_vuln",
        "vulnerability_treatments",
        [
            sa.text("project_uuid"),
            sa.text("vuln_key"),
            sa.text("component_name"),
            sa.text("COALESCE(component_version, '')"),
        ],
        unique=True,
        sqlite_where=sa.text(f"estado IN ({_ACTIVE_STATES_SQL}) AND activo_en_plan = 1"),
        postgresql_where=sa.text(f"estado IN ({_ACTIVE_STATES_SQL}) AND activo_en_plan = 1"),
    )


def downgrade() -> None:
    op.drop_index("uq_treatment_active_project_vuln", table_name="vulnerability_treatments")
    op.create_index(
        "uq_treatment_active_project_vuln",
        "vulnerability_treatments",
        ["project_uuid", "vuln_key"],
        unique=True,
        sqlite_where=sa.text(f"estado IN ({_ACTIVE_STATES_SQL})"),
        postgresql_where=sa.text(f"estado IN ({_ACTIVE_STATES_SQL})"),
    )

    with op.batch_alter_table("vulnerability_treatments") as batch_op:
        batch_op.drop_column("activo_en_plan")
        batch_op.drop_column("finalizacion_subtipo")
        batch_op.drop_column("component_version")
        batch_op.drop_column("component_name")

    op.drop_index("uq_findings_identity", table_name="findings")

    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_column("ultima_reaparicion_at")
        batch_op.drop_column("reaparicion_count")
        batch_op.drop_column("es_reincidente")
        batch_op.drop_column("resuelta_at")
        batch_op.drop_column("ultima_vista_at")
        batch_op.drop_column("primera_deteccion_at")
        batch_op.drop_column("estado_ciclo_vida")
