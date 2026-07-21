"""Fix findings unique constraint: project_uuid + dt_finding_uuid

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-30

El constraint anterior era inline sin nombre: UNIQUE (dt_finding_uuid).
SQLite no permite DROP CONSTRAINT por nombre cuando no tiene nombre, así que
se recrea la tabla completa con el constraint compuesto nombrado.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE findings_new (
            id INTEGER NOT NULL,
            project_uuid VARCHAR(36) NOT NULL,
            dt_finding_uuid VARCHAR(36) NOT NULL,
            component_name VARCHAR(255) NOT NULL,
            component_version VARCHAR(100),
            component_group VARCHAR(255),
            vuln_id VARCHAR(100) NOT NULL,
            vuln_source VARCHAR(50) NOT NULL,
            severity VARCHAR(20) NOT NULL,
            cvss_v3_base_score FLOAT,
            epss_score FLOAT,
            epss_percentile FLOAT,
            attributed_on DATETIME,
            suppressed BOOLEAN DEFAULT '0' NOT NULL,
            last_synced_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            PRIMARY KEY (id),
            FOREIGN KEY(project_uuid) REFERENCES projects (uuid) ON DELETE CASCADE,
            CONSTRAINT uq_findings_project_dt_uuid UNIQUE (project_uuid, dt_finding_uuid)
        )
    """)
    op.execute("INSERT INTO findings_new SELECT * FROM findings")
    op.execute("DROP TABLE findings")
    op.execute("ALTER TABLE findings_new RENAME TO findings")
    op.execute(
        "CREATE INDEX ix_findings_project_severity ON findings (project_uuid, severity)"
    )
    op.execute("CREATE INDEX ix_findings_vuln_id ON findings (vuln_id)")
    op.execute("CREATE INDEX ix_findings_attributed_on ON findings (attributed_on)")


def downgrade() -> None:
    op.execute("""
        CREATE TABLE findings_old (
            id INTEGER NOT NULL,
            project_uuid VARCHAR(36) NOT NULL,
            dt_finding_uuid VARCHAR(36) NOT NULL,
            component_name VARCHAR(255) NOT NULL,
            component_version VARCHAR(100),
            component_group VARCHAR(255),
            vuln_id VARCHAR(100) NOT NULL,
            vuln_source VARCHAR(50) NOT NULL,
            severity VARCHAR(20) NOT NULL,
            cvss_v3_base_score FLOAT,
            epss_score FLOAT,
            epss_percentile FLOAT,
            attributed_on DATETIME,
            suppressed BOOLEAN DEFAULT '0' NOT NULL,
            last_synced_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            PRIMARY KEY (id),
            FOREIGN KEY(project_uuid) REFERENCES projects (uuid) ON DELETE CASCADE,
            UNIQUE (dt_finding_uuid)
        )
    """)
    op.execute("INSERT INTO findings_old SELECT * FROM findings")
    op.execute("DROP TABLE findings")
    op.execute("ALTER TABLE findings_old RENAME TO findings")
    op.execute(
        "CREATE INDEX ix_findings_project_severity ON findings (project_uuid, severity)"
    )
    op.execute("CREATE INDEX ix_findings_vuln_id ON findings (vuln_id)")
    op.execute("CREATE INDEX ix_findings_attributed_on ON findings (attributed_on)")
