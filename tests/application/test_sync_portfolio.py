"""Tests T-061: SyncPortfolioUseCase."""
from __future__ import annotations

import logging
from datetime import UTC, date, datetime
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx

from vulntrack.application.sync.sync_portfolio import (
    SyncPortfolioUseCase,
    _dt_finding_to_domain,
)
from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.metric_snapshot import MetricSnapshot, SnapshotSource
from vulntrack.domain.entities.project import Project
from vulntrack.domain.value_objects.severity import Severity
from vulntrack.infrastructure.dt.response_models import DtFinding, DtMetrics, DtProject


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _dt_project(name: str = "proj-a", uuid: str = "uuid-a") -> dict:
    return {"uuid": uuid, "name": name, "version": None, "description": None, "lastBomImport": None}


def _dt_metrics(critical: int = 2, high: int = 5) -> dict:
    return {
        "critical": critical, "high": high, "medium": 3,
        "low": 1, "unassigned": 0, "inheritedRiskScore": 6.5, "total": critical + high + 4,
    }


def _make_repos(historical_count: int = 0):
    project_repo = AsyncMock()
    finding_repo = AsyncMock()
    snapshot_repo = AsyncMock()
    snapshot_repo.count_by_source.return_value = historical_count
    snapshot_repo.upsert.return_value = None
    finding_repo.upsert_batch.return_value = None
    project_repo.upsert.return_value = None
    return project_repo, finding_repo, snapshot_repo


# ─── Tests ────────────────────────────────────────────────────────────────────

class TestSyncPortfolioUseCase:
    @pytest.mark.asyncio
    async def test_sync_three_projects_all_ok(self) -> None:
        project_repo, finding_repo, snapshot_repo = _make_repos(historical_count=1)
        dt_client = AsyncMock()
        dt_client.get_all_projects.return_value = [
            _dt_project("proj-a", "u-a"),
            _dt_project("proj-b", "u-b"),
            _dt_project("proj-c", "u-c"),
        ]
        dt_client.get_project_metrics.return_value = _dt_metrics()
        dt_client.get_project_findings.return_value = []

        uc = SyncPortfolioUseCase(dt_client, project_repo, finding_repo, snapshot_repo)
        result = await uc.execute()

        assert result.synced_projects == 3
        assert result.failed_projects == 0
        assert result.errors == []
        assert result.duration_seconds >= 0

    @pytest.mark.asyncio
    async def test_one_project_fails_others_continue(self) -> None:
        project_repo, finding_repo, snapshot_repo = _make_repos(historical_count=1)
        dt_client = AsyncMock()
        dt_client.get_all_projects.return_value = [
            _dt_project("good", "u-good"),
            _dt_project("bad", "u-bad"),
        ]

        async def metrics_side_effect(uuid: str) -> object:
            if uuid == "u-bad":
                raise ConnectionError("DT unreachable")
            return _dt_metrics()

        dt_client.get_project_metrics.side_effect = metrics_side_effect
        dt_client.get_project_findings.return_value = []

        uc = SyncPortfolioUseCase(dt_client, project_repo, finding_repo, snapshot_repo)
        result = await uc.execute()

        assert result.synced_projects == 1
        assert result.failed_projects == 1
        assert len(result.errors) == 1
        assert "bad" in result.errors[0]

    @pytest.mark.asyncio
    async def test_fetch_projects_fails_returns_early(self) -> None:
        project_repo, finding_repo, snapshot_repo = _make_repos()
        dt_client = AsyncMock()
        dt_client.get_all_projects.side_effect = TimeoutError("timeout")

        uc = SyncPortfolioUseCase(dt_client, project_repo, finding_repo, snapshot_repo)
        result = await uc.execute()

        assert result.synced_projects == 0
        assert result.failed_projects == 0
        assert len(result.errors) == 1

    @pytest.mark.asyncio
    async def test_idempotent_two_syncs_no_duplicates(self) -> None:
        project_repo, finding_repo, snapshot_repo = _make_repos(historical_count=1)
        dt_client = AsyncMock()
        dt_client.get_all_projects.return_value = [_dt_project()]
        dt_client.get_project_metrics.return_value = _dt_metrics()
        dt_client.get_project_findings.return_value = []

        uc = SyncPortfolioUseCase(dt_client, project_repo, finding_repo, snapshot_repo)
        await uc.execute()
        await uc.execute()

        # upsert is idempotent by design; called twice (one per sync)
        assert snapshot_repo.upsert.call_count == 2

    @pytest.mark.asyncio
    async def test_backfill_triggered_on_first_sync(self) -> None:
        project_repo, finding_repo, snapshot_repo = _make_repos(historical_count=0)
        dt_client = AsyncMock()
        dt_client.get_all_projects.return_value = [_dt_project()]
        dt_client.get_project_metrics.return_value = _dt_metrics()
        dt_client.get_project_findings.return_value = []
        # Simulate 5 historical records (each with a different date via first_occurrence)
        dt_client.get_project_metric_history.return_value = [
            {
                "critical": 1, "high": 2, "medium": 3, "low": 1, "unassigned": 0,
                "inheritedRiskScore": 5.0, "total": 7,
                "firstOccurrence": f"2026-04-0{i}T00:00:00Z",
                "lastOccurrence": f"2026-04-0{i}T00:00:00Z",
            }
            for i in range(1, 4)
        ]

        uc = SyncPortfolioUseCase(dt_client, project_repo, finding_repo, snapshot_repo)
        result = await uc.execute()

        assert result.synced_projects == 1
        dt_client.get_project_metric_history.assert_called_once()

    # ── T-B005: findings error tolerance ──────────────────────────────────────

    @pytest.mark.asyncio
    async def test_findings_failure_does_not_fail_project(self) -> None:
        """Si get_project_findings falla, el proyecto se cuenta como synced (métricas OK)."""
        project_repo, finding_repo, snapshot_repo = _make_repos(historical_count=1)
        dt_client = AsyncMock()
        dt_client.get_all_projects.return_value = [_dt_project()]
        dt_client.get_project_metrics.return_value = _dt_metrics()

        fake_request = httpx.Request("GET", "http://dt/api/v1/finding/project/uuid-a")
        fake_response = httpx.Response(403, request=fake_request)
        dt_client.get_project_findings.side_effect = httpx.HTTPStatusError(
            "Forbidden", request=fake_request, response=fake_response
        )

        uc = SyncPortfolioUseCase(dt_client, project_repo, finding_repo, snapshot_repo)
        result = await uc.execute()

        assert result.synced_projects == 1
        assert result.failed_projects == 0
        assert result.errors == []
        finding_repo.upsert_batch.assert_not_called()

    @pytest.mark.asyncio
    async def test_findings_empty_with_nonzero_metrics_logs_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """findings=[] cuando métricas son >0 emite WARNING con el nombre del proyecto."""
        project_repo, finding_repo, snapshot_repo = _make_repos(historical_count=1)
        dt_client = AsyncMock()
        dt_client.get_all_projects.return_value = [_dt_project("proj-a", "uuid-a")]
        dt_client.get_project_metrics.return_value = _dt_metrics(critical=5, high=10)
        dt_client.get_project_findings.return_value = []

        uc = SyncPortfolioUseCase(dt_client, project_repo, finding_repo, snapshot_repo)
        with caplog.at_level(logging.WARNING):
            await uc.execute()

        assert "sync_findings_empty_but_metrics_nonzero" in caplog.text
        assert "proj-a" in caplog.text

    @pytest.mark.asyncio
    async def test_findings_http_error_logs_status_code(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """HTTPStatusError en findings loguea el status code en WARNING."""
        project_repo, finding_repo, snapshot_repo = _make_repos(historical_count=1)
        dt_client = AsyncMock()
        dt_client.get_all_projects.return_value = [_dt_project()]
        dt_client.get_project_metrics.return_value = _dt_metrics()

        fake_request = httpx.Request("GET", "http://dt/api/v1/finding/project/uuid-a")
        fake_response = httpx.Response(403, request=fake_request)
        dt_client.get_project_findings.side_effect = httpx.HTTPStatusError(
            "Forbidden", request=fake_request, response=fake_response
        )

        uc = SyncPortfolioUseCase(dt_client, project_repo, finding_repo, snapshot_repo)
        with caplog.at_level(logging.WARNING):
            await uc.execute()

        assert "sync_findings_http_error" in caplog.text
        assert "403" in caplog.text

    # ── T-B006: last_sync_at ──────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_last_sync_at_updated_after_execute(self) -> None:
        """app_settings_repo.update se llama con last_sync_at después del sync."""
        project_repo, finding_repo, snapshot_repo = _make_repos(historical_count=1)
        dt_client = AsyncMock()
        dt_client.get_all_projects.return_value = [_dt_project()]
        dt_client.get_project_metrics.return_value = _dt_metrics()
        dt_client.get_project_findings.return_value = []

        app_settings_repo = AsyncMock()

        uc = SyncPortfolioUseCase(
            dt_client, project_repo, finding_repo, snapshot_repo,
            app_settings_repo=app_settings_repo,
        )
        await uc.execute()

        app_settings_repo.update.assert_called_once()
        call_kwargs = app_settings_repo.update.call_args.kwargs
        assert "last_sync_at" in call_kwargs
        assert isinstance(call_kwargs["last_sync_at"], datetime)

    @pytest.mark.asyncio
    async def test_last_sync_at_not_updated_when_repo_none(self) -> None:
        """Sin app_settings_repo el sync completa normalmente sin excepción."""
        project_repo, finding_repo, snapshot_repo = _make_repos(historical_count=1)
        dt_client = AsyncMock()
        dt_client.get_all_projects.return_value = [_dt_project()]
        dt_client.get_project_metrics.return_value = _dt_metrics()
        dt_client.get_project_findings.return_value = []

        uc = SyncPortfolioUseCase(dt_client, project_repo, finding_repo, snapshot_repo)
        result = await uc.execute()
        assert result.synced_projects == 1

    @pytest.mark.asyncio
    async def test_last_sync_at_update_failure_does_not_abort_sync(self) -> None:
        """Si update de last_sync_at falla, el resultado del sync no cambia."""
        project_repo, finding_repo, snapshot_repo = _make_repos(historical_count=1)
        dt_client = AsyncMock()
        dt_client.get_all_projects.return_value = [_dt_project()]
        dt_client.get_project_metrics.return_value = _dt_metrics()
        dt_client.get_project_findings.return_value = []

        app_settings_repo = AsyncMock()
        app_settings_repo.update.side_effect = RuntimeError("DB error")

        uc = SyncPortfolioUseCase(
            dt_client, project_repo, finding_repo, snapshot_repo,
            app_settings_repo=app_settings_repo,
        )
        result = await uc.execute()
        assert result.synced_projects == 1

    @pytest.mark.asyncio
    async def test_backfill_skipped_on_subsequent_sync(self) -> None:
        project_repo, finding_repo, snapshot_repo = _make_repos(historical_count=100)
        dt_client = AsyncMock()
        dt_client.get_all_projects.return_value = [_dt_project()]
        dt_client.get_project_metrics.return_value = _dt_metrics()
        dt_client.get_project_findings.return_value = []

        uc = SyncPortfolioUseCase(dt_client, project_repo, finding_repo, snapshot_repo)
        await uc.execute()

        dt_client.get_project_metric_history.assert_not_called()


# ── T-C011: _dt_finding_to_domain — cve_id / cvss fallback / suppressed ───────

class TestDtFindingToDomain:
    def _raw(self, **vuln_overrides: object) -> dict:
        vulnerability = {"vulnId": "GHSA-xxxx", "source": "GITHUB", "aliases": []}
        vulnerability.update(vuln_overrides)
        return {
            "component": {"name": "lib", "uuid": "comp-uuid"},
            "vulnerability": vulnerability,
            "analysis": {"isSuppressed": False},
        }

    def test_cve_id_extracted_from_alias(self) -> None:
        raw = self._raw(aliases=[{"cveId": "CVE-2024-1", "ghsaId": "GHSA-xxxx"}])
        f = DtFinding.model_validate(raw)
        finding = _dt_finding_to_domain("proj-a", f, datetime(2026, 6, 30, tzinfo=UTC))
        assert finding.cve_id == "CVE-2024-1"

    def test_cvss_score_computed_from_vector_when_base_score_missing(self) -> None:
        raw = self._raw(
            cvssV3Vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        )
        f = DtFinding.model_validate(raw)
        finding = _dt_finding_to_domain("proj-a", f, datetime(2026, 6, 30, tzinfo=UTC))
        assert finding.cvss_v3_base_score == pytest.approx(7.5)

    def test_cvss_base_score_used_directly_without_parsing_vector(self) -> None:
        raw = self._raw(
            cvssV3BaseScore=9.1,
            cvssV3Vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        )
        f = DtFinding.model_validate(raw)
        finding = _dt_finding_to_domain("proj-a", f, datetime(2026, 6, 30, tzinfo=UTC))
        assert finding.cvss_v3_base_score == 9.1

    def test_suppressed_true_from_is_suppressed_alias(self) -> None:
        raw = self._raw()
        raw["analysis"] = {"isSuppressed": True}
        f = DtFinding.model_validate(raw)
        finding = _dt_finding_to_domain("proj-a", f, datetime(2026, 6, 30, tzinfo=UTC))
        assert finding.suppressed is True
