"""Tests T-063: DashboardQuery."""
from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from vulntrack.application.queries.dashboard_query import DashboardQuery
from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.kev_entry import KevEntry
from vulntrack.domain.entities.project import Project
from vulntrack.domain.value_objects.severity import Severity


def _project(uuid: str, name: str = "proj") -> Project:
    return Project(uuid=uuid, name=name, version=None, description=None,
                   last_bom_import=None, last_synced_at=datetime.now(UTC))


def _finding(uuid: str, project_uuid: str, severity: Severity, vuln_id: str = "CVE-X") -> Finding:
    return Finding(
        id=1, project_uuid=project_uuid, dt_finding_uuid=f"dt-{uuid}",
        component_name="comp", component_version=None, component_group=None,
        vuln_id=vuln_id, vuln_source="NVD", severity=severity,
        cvss_v3_base_score=7.5, epss_score=0.1, epss_percentile=None,
        attributed_on=None, suppressed=False, last_synced_at=datetime.now(UTC),
    )


def _kev_entry(cve_id: str) -> KevEntry:
    from datetime import date
    return KevEntry(
        cve_id=cve_id, vendor_project="V", product="P", vulnerability_name="V",
        date_added=date(2026, 1, 1), short_description="d",
        required_action="patch", due_date=None, notes=None,
    )


class TestDashboardQuery:
    @pytest.mark.asyncio
    async def test_kpis_with_data(self) -> None:
        project_repo = AsyncMock()
        project_repo.list_all.return_value = [
            _project("u1", "proj-a"),
            _project("u2", "proj-b"),
        ]
        finding_repo = AsyncMock()
        finding_repo.list_all_active.return_value = [
            _finding("f1", "u1", Severity.CRITICAL, "CVE-2024-1234"),
            _finding("f2", "u1", Severity.HIGH),
            _finding("f3", "u2", Severity.MEDIUM),
        ]
        kev_repo = AsyncMock()
        kev_repo.list_all.return_value = [_kev_entry("CVE-2024-1234")]
        kev_repo.get_catalog_meta.return_value = None

        q = DashboardQuery(project_repo, finding_repo, kev_repo)
        data = await q.execute()

        assert data.total_vigentes == 3
        assert data.vigentes_por_severidad[Severity.CRITICAL] == 1
        assert data.vigentes_por_severidad[Severity.HIGH] == 1
        assert data.vigentes_por_severidad[Severity.MEDIUM] == 1
        assert data.proyectos_con_criticas == 1
        assert data.proyectos_en_cero == 0
        assert data.kev_hits_count == 1
        assert data.total_proyectos == 2

    @pytest.mark.asyncio
    async def test_proyecto_en_cero(self) -> None:
        project_repo = AsyncMock()
        project_repo.list_all.return_value = [_project("u1"), _project("u2")]
        finding_repo = AsyncMock()
        # Only u1 has findings; u2 has none
        finding_repo.list_all_active.return_value = [
            _finding("f1", "u1", Severity.LOW),
        ]
        kev_repo = AsyncMock()
        kev_repo.list_all.return_value = []
        kev_repo.get_catalog_meta.return_value = None

        q = DashboardQuery(project_repo, finding_repo, kev_repo)
        data = await q.execute()

        assert data.proyectos_en_cero == 1

    @pytest.mark.asyncio
    async def test_empty_portfolio(self) -> None:
        project_repo = AsyncMock()
        project_repo.list_all.return_value = []
        finding_repo = AsyncMock()
        finding_repo.list_all_active.return_value = []
        kev_repo = AsyncMock()
        kev_repo.list_all.return_value = []
        kev_repo.get_catalog_meta.return_value = None

        q = DashboardQuery(project_repo, finding_repo, kev_repo)
        data = await q.execute()

        assert data.total_vigentes == 0
        assert data.kev_hits_count == 0
        assert data.total_proyectos == 0
