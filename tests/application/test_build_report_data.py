"""Tests T-065: BuildReportDataUseCase."""
from __future__ import annotations

from datetime import UTC, date, datetime
from unittest.mock import AsyncMock

import pytest

from vulntrack.application.reports.build_report_data import BuildReportDataUseCase
from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.kev_entry import KevEntry
from vulntrack.domain.entities.metric_snapshot import MetricSnapshot, SnapshotSource
from vulntrack.domain.entities.project import Project
from vulntrack.domain.value_objects.date_range import DateRange
from vulntrack.domain.value_objects.severity import Severity


def _project(uuid: str, name: str = "proj") -> Project:
    return Project(uuid=uuid, name=name, version=None, description=None,
                   last_bom_import=None, last_synced_at=datetime.now(UTC))


def _finding(f_id: int, proj_uuid: str, sev: Severity, vuln_id: str = "CVE-X") -> Finding:
    return Finding(
        id=f_id, project_uuid=proj_uuid, dt_finding_uuid=f"dt-{f_id}",
        component_name="comp", component_version="1.0", component_group=None,
        vuln_id=vuln_id, vuln_source="NVD", severity=sev,
        cvss_v3_base_score=7.5, epss_score=0.2, epss_percentile=None,
        attributed_on=datetime(2026, 5, 1, tzinfo=UTC), suppressed=False,
        last_synced_at=datetime.now(UTC),
    )


def _snapshot(
    proj_uuid: str, snap_date: date,
    critical: int = 2, high: int = 3, medium: int = 3, low: int = 2,
) -> MetricSnapshot:
    total_assigned = critical + high + medium + low
    return MetricSnapshot(
        id=1, project_uuid=proj_uuid, snapshot_date=snap_date,
        critical=critical, high=high, medium=medium, low=low, unassigned=0,
        total=total_assigned, risk_score=6.5, source=SnapshotSource.DT_CURRENT,
    )


def _kev(cve_id: str) -> KevEntry:
    return KevEntry(cve_id=cve_id, vendor_project="V", product="P",
                    vulnerability_name="V", date_added=date(2026, 1, 1),
                    short_description="d", required_action="patch",
                    due_date=None, notes=None)


class TestBuildReportDataUseCase:
    def _make_uc(
        self,
        projects: list[Project],
        all_findings: list[Finding],
        new_findings: list[Finding],
        kev_entries: list[KevEntry] = [],
        inicio_snap: MetricSnapshot | None = None,
        actual_snap: MetricSnapshot | None = None,
    ) -> BuildReportDataUseCase:
        project_repo = AsyncMock()
        project_repo.list_all.return_value = projects
        finding_repo = AsyncMock()
        finding_repo.list_all_active.return_value = all_findings
        finding_repo.get_new_in_range.return_value = new_findings
        snapshot_repo = AsyncMock()
        snapshot_repo.get_closest_before.side_effect = lambda uuid, d: (
            inicio_snap if d == date(2026, 4, 1) else actual_snap
        )
        kev_repo = AsyncMock()
        kev_repo.list_all.return_value = kev_entries

        return BuildReportDataUseCase(
            project_repo, finding_repo, snapshot_repo, kev_repo,
            author="Test Author",
        )

    @pytest.mark.asyncio
    async def test_kpis_vigentes_nuevas_tratadas(self) -> None:
        proj = _project("u1", "daviplata-webview-frontend")
        # total_assigned() = critical+high+medium+low = 30+40+30+18 = 118
        inicio_snap = _snapshot("u1", date(2026, 4, 1), critical=30, high=40, medium=30, low=18)
        # total_assigned() = 25+35+25+12 = 97
        actual_snap = _snapshot("u1", date(2026, 6, 30), critical=25, high=35, medium=25, low=12)

        all_findings = [_finding(i, "u1", Severity.HIGH) for i in range(97)]
        new_findings = [_finding(200 + i, "u1", Severity.HIGH) for i in range(118)]

        uc = self._make_uc(
            [proj], all_findings, new_findings,
            inicio_snap=inicio_snap, actual_snap=actual_snap,
        )
        dr = DateRange(date(2026, 4, 1), date(2026, 6, 30))
        data = await uc.execute(dr, "Q2 2026")

        assert data.total_vigentes == 97
        assert data.total_nuevas == 118
        # tratadas = max(0, inicio.total_assigned() - actual.total_assigned()) = 118 - 97 = 21
        assert data.total_tratadas == 21
        assert data.period_label == "Q2 2026"
        assert data.author == "Test Author"

    @pytest.mark.asyncio
    async def test_kev_hits_extracted(self) -> None:
        proj = _project("u1")
        finding_kev = _finding(1, "u1", Severity.CRITICAL, vuln_id="CVE-2024-1234")
        finding_no_kev = _finding(2, "u1", Severity.HIGH, vuln_id="CVE-SAFE")

        uc = self._make_uc(
            [proj], [finding_kev, finding_no_kev], [],
            kev_entries=[_kev("CVE-2024-1234")],
        )
        dr = DateRange(date(2026, 4, 1), date(2026, 6, 30))
        data = await uc.execute(dr, "Q2 2026")

        kev_ids = {r.vuln_id for r in data.kev_hits}
        assert "CVE-2024-1234" in kev_ids
        assert "CVE-SAFE" not in kev_ids

    @pytest.mark.asyncio
    async def test_project_filter(self) -> None:
        proj_a = _project("u-a", "proj-a")
        proj_b = _project("u-b", "proj-b")
        findings_a = [_finding(1, "u-a", Severity.MEDIUM)]
        findings_b = [_finding(2, "u-b", Severity.HIGH)]

        project_repo = AsyncMock()
        project_repo.list_all.return_value = [proj_a, proj_b]
        finding_repo = AsyncMock()
        # active returns both but we filter by project_uuid
        finding_repo.list_all_active.return_value = findings_a  # filtered externally
        finding_repo.get_new_in_range.return_value = []
        snapshot_repo = AsyncMock()
        snapshot_repo.get_closest_before.return_value = None
        kev_repo = AsyncMock()
        kev_repo.list_all.return_value = []

        uc = BuildReportDataUseCase(
            project_repo, finding_repo, snapshot_repo, kev_repo
        )
        dr = DateRange(date(2026, 4, 1), date(2026, 6, 30))
        data = await uc.execute(dr, "Q2", project_uuids=["u-a"])

        assert len(data.project_rows) == 1
        assert data.project_rows[0].name == "proj-a"

    @pytest.mark.asyncio
    async def test_prioritized_findings_sorted_by_score(self) -> None:
        proj = _project("u1")
        findings = [
            _finding(1, "u1", Severity.LOW, "CVE-LOW"),
            _finding(2, "u1", Severity.CRITICAL, "CVE-CRIT"),
        ]
        # Patch cvss/epss on CRITICAL to give high score
        findings[1].cvss_v3_base_score = 9.8
        findings[1].epss_score = 0.9

        uc = self._make_uc([proj], findings, [])
        dr = DateRange(date(2026, 4, 1), date(2026, 6, 30))
        data = await uc.execute(dr, "Q2")

        assert len(data.prioritized_findings) == 2
        assert data.prioritized_findings[0].vuln_id == "CVE-CRIT"
