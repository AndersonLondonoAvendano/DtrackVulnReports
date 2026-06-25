"""Tests T-061: SyncPortfolioUseCase."""
from __future__ import annotations

from datetime import UTC, date, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from vulntrack.application.sync.sync_portfolio import SyncPortfolioUseCase
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
