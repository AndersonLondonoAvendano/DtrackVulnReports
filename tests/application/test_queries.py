"""Tests T-064: ProjectDetailQuery y PrioritizedFindingsQuery."""
from __future__ import annotations

from datetime import UTC, date, datetime
from unittest.mock import AsyncMock

import pytest

from vulntrack.application.queries.prioritized_findings_query import PrioritizedFindingsQuery
from vulntrack.application.queries.project_detail_query import ProjectDetailQuery
from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.kev_entry import KevEntry
from vulntrack.domain.entities.project import Project
from vulntrack.domain.exceptions import ProjectNotFoundError
from vulntrack.domain.services.kev_matcher import KevMatcher
from vulntrack.domain.value_objects.severity import Severity


def _project(uuid: str = "u1") -> Project:
    return Project(uuid=uuid, name="proj", version=None, description=None,
                   last_bom_import=None, last_synced_at=datetime.now(UTC))


def _finding(
    f_id: int = 1, project_uuid: str = "u1",
    severity: Severity = Severity.CRITICAL,
    vuln_id: str = "CVE-2024-0001",
    cvss: float | None = 9.8, epss: float | None = 0.85,
) -> Finding:
    return Finding(
        id=f_id, project_uuid=project_uuid, dt_finding_uuid=f"dt-{f_id}",
        component_name="comp", component_version="1.0", component_group=None,
        vuln_id=vuln_id, vuln_source="NVD", severity=severity,
        cvss_v3_base_score=cvss, epss_score=epss, epss_percentile=None,
        attributed_on=None, suppressed=False, last_synced_at=datetime.now(UTC),
    )


def _kev(cve_id: str) -> KevEntry:
    return KevEntry(cve_id=cve_id, vendor_project="V", product="P",
                    vulnerability_name="V", date_added=date(2026, 1, 1),
                    short_description="d", required_action="patch",
                    due_date=None, notes=None)


class TestPrioritizedFindingsQuery:
    def _make_query(self, findings: list[Finding], kev_ids: list[str] = []) -> PrioritizedFindingsQuery:
        repo = AsyncMock()
        repo.list_all_active.return_value = findings
        matcher = KevMatcher([_kev(c) for c in kev_ids])
        return PrioritizedFindingsQuery(repo, matcher)

    @pytest.mark.asyncio
    async def test_sorted_by_score_desc(self) -> None:
        findings = [
            _finding(1, severity=Severity.LOW, cvss=2.0, epss=0.01),
            _finding(2, severity=Severity.CRITICAL, vuln_id="CVE-A", cvss=9.8, epss=0.85),
            _finding(3, severity=Severity.MEDIUM, cvss=5.0, epss=0.20),
        ]
        q = self._make_query(findings, kev_ids=["CVE-A"])
        result = await q.execute()

        assert len(result) == 3
        # KEV finding (CVE-A) must be first
        assert result[0].finding.vuln_id == "CVE-A"
        assert result[0].score.is_kev is True
        # Scores must be descending
        scores = [r.score.value for r in result]
        assert scores == sorted(scores, reverse=True)

    @pytest.mark.asyncio
    async def test_kev_only_filter(self) -> None:
        findings = [
            _finding(1, vuln_id="CVE-KEV", cvss=9.8, epss=0.9),
            _finding(2, vuln_id="CVE-NOT-KEV", cvss=7.0, epss=0.1),
        ]
        q = self._make_query(findings, kev_ids=["CVE-KEV"])
        result = await q.execute(kev_only=True)

        assert len(result) == 1
        assert result[0].finding.vuln_id == "CVE-KEV"

    @pytest.mark.asyncio
    async def test_min_cvss_filter(self) -> None:
        findings = [
            _finding(1, cvss=9.0, epss=0.0),
            _finding(2, cvss=4.0, epss=0.0),
        ]
        q = self._make_query(findings)
        result = await q.execute(min_cvss=7.0)

        assert len(result) == 1
        assert result[0].finding.cvss_v3_base_score == 9.0

    @pytest.mark.asyncio
    async def test_min_epss_filter(self) -> None:
        findings = [
            _finding(1, epss=0.80),
            _finding(2, epss=0.10),
        ]
        q = self._make_query(findings)
        result = await q.execute(min_epss=0.5)

        assert len(result) == 1
        assert result[0].finding.epss_score == 0.80


class TestProjectDetailQuery:
    @pytest.mark.asyncio
    async def test_raises_if_project_not_found(self) -> None:
        project_repo = AsyncMock()
        project_repo.get_by_uuid.return_value = None
        finding_repo = AsyncMock()
        snapshot_repo = AsyncMock()
        remediation_repo = AsyncMock()
        matcher = KevMatcher([])

        q = ProjectDetailQuery(
            project_repo, finding_repo, snapshot_repo, remediation_repo, matcher
        )
        with pytest.raises(ProjectNotFoundError):
            await q.execute("missing-uuid")

    @pytest.mark.asyncio
    async def test_findings_sorted_by_priority_desc(self) -> None:
        project_repo = AsyncMock()
        project_repo.get_by_uuid.return_value = _project("u1")
        finding_repo = AsyncMock()
        finding_repo.list_by_project.return_value = [
            _finding(1, cvss=2.0, epss=0.01),
            _finding(2, vuln_id="CVE-KEV", cvss=9.8, epss=0.9),
        ]
        snapshot_repo = AsyncMock()
        snapshot_repo.get_closest_before.return_value = None
        remediation_repo = AsyncMock()
        remediation_repo.list_plans_by_project.return_value = []
        matcher = KevMatcher([_kev("CVE-KEV")])

        q = ProjectDetailQuery(
            project_repo, finding_repo, snapshot_repo, remediation_repo, matcher
        )
        detail = await q.execute("u1")

        assert len(detail.prioritized_findings) == 2
        assert detail.prioritized_findings[0].finding.vuln_id == "CVE-KEV"
