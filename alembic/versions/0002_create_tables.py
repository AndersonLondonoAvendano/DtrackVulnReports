"""Crear schema inicial completo

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-24

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("uuid", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(100)),
        sa.Column("description", sa.Text),
        sa.Column("last_bom_import", sa.DateTime),
        sa.Column("last_synced_at", sa.DateTime, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "metric_snapshots",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("project_uuid", sa.String(36), sa.ForeignKey("projects.uuid", ondelete="CASCADE"), nullable=False),
        sa.Column("snapshot_date", sa.Date, nullable=False),
        sa.Column("critical", sa.Integer, nullable=False, server_default="0"),
        sa.Column("high", sa.Integer, nullable=False, server_default="0"),
        sa.Column("medium", sa.Integer, nullable=False, server_default="0"),
        sa.Column("low", sa.Integer, nullable=False, server_default="0"),
        sa.Column("unassigned", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total", sa.Integer, nullable=False, server_default="0"),
        sa.Column("risk_score", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("source", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_metric_snapshots_project_date", "metric_snapshots", ["project_uuid", "snapshot_date"])

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("project_uuid", sa.String(36), sa.ForeignKey("projects.uuid", ondelete="CASCADE"), nullable=False),
        sa.Column("dt_finding_uuid", sa.String(36), nullable=False, unique=True),
        sa.Column("component_name", sa.String(255), nullable=False),
        sa.Column("component_version", sa.String(100)),
        sa.Column("component_group", sa.String(255)),
        sa.Column("vuln_id", sa.String(100), nullable=False),
        sa.Column("vuln_source", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("cvss_v3_base_score", sa.Float),
        sa.Column("epss_score", sa.Float),
        sa.Column("epss_percentile", sa.Float),
        sa.Column("attributed_on", sa.DateTime),
        sa.Column("suppressed", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("last_synced_at", sa.DateTime, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_findings_project_severity", "findings", ["project_uuid", "severity"])
    op.create_index("ix_findings_vuln_id", "findings", ["vuln_id"])
    op.create_index("ix_findings_attributed_on", "findings", ["attributed_on"])

    op.create_table(
        "kev_entries",
        sa.Column("cve_id", sa.String(30), primary_key=True),
        sa.Column("vendor_project", sa.String(255), nullable=False),
        sa.Column("product", sa.String(255), nullable=False),
        sa.Column("vulnerability_name", sa.String(500), nullable=False),
        sa.Column("date_added", sa.Date, nullable=False),
        sa.Column("short_description", sa.Text, nullable=False),
        sa.Column("required_action", sa.Text, nullable=False),
        sa.Column("due_date", sa.Date),
        sa.Column("notes", sa.Text),
        sa.Column("catalog_updated_at", sa.DateTime),
    )

    op.create_table(
        "remediation_plans",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("project_uuid", sa.String(36), sa.ForeignKey("projects.uuid", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "remediation_tasks",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("plan_id", sa.Integer, sa.ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", sa.Integer, sa.ForeignKey("findings.id", ondelete="SET NULL")),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("assignee", sa.String(255)),
        sa.Column("status", sa.String(20), nullable=False, server_default="PENDING"),
        sa.Column("priority_band", sa.String(20), nullable=False),
        sa.Column("recommended_action", sa.Text),
        sa.Column("target_date", sa.Date),
        sa.Column("completed_at", sa.DateTime),
        sa.Column("notes", sa.Text),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "app_settings",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("sync_interval_hours", sa.Integer, nullable=False, server_default="6"),
        sa.Column("kev_stale_days", sa.Integer, nullable=False, server_default="7"),
        sa.Column("last_sync_at", sa.DateTime),
        sa.Column("last_kev_update_at", sa.DateTime),
        sa.Column("w_cvss_weight", sa.Float, nullable=False, server_default="0.30"),
        sa.Column("w_epss_weight", sa.Float, nullable=False, server_default="0.40"),
        sa.Column("w_kev_weight", sa.Float, nullable=False, server_default="0.30"),
        sa.Column("kev_minimum_score", sa.Float, nullable=False, server_default="0.75"),
        sa.Column("epss_high_threshold", sa.Float, nullable=False, server_default="0.40"),
        sa.Column("cvss_high_threshold", sa.Float, nullable=False, server_default="7.0"),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("app_settings")
    op.drop_table("remediation_tasks")
    op.drop_table("remediation_plans")
    op.drop_table("kev_entries")
    op.drop_index("ix_findings_attributed_on", table_name="findings")
    op.drop_index("ix_findings_vuln_id", table_name="findings")
    op.drop_index("ix_findings_project_severity", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_metric_snapshots_project_date", table_name="metric_snapshots")
    op.drop_table("metric_snapshots")
    op.drop_table("projects")
