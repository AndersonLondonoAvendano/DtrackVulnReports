from __future__ import annotations

from datetime import UTC, date, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.kev_entry import KevEntry
from vulntrack.domain.entities.metric_snapshot import MetricSnapshot, SnapshotSource
from vulntrack.domain.entities.project import Project
from vulntrack.domain.entities.remediation import TaskStatus
from vulntrack.domain.value_objects.priority_score import PriorityBand
from vulntrack.domain.value_objects.severity import Severity
from vulntrack.infrastructure.persistence.repositories.app_settings_repo import (
    SqliteAppSettingsRepository,
)
from vulntrack.infrastructure.persistence.repositories.finding_repo import SqliteFindingRepository
from vulntrack.infrastructure.persistence.repositories.kev_repo import SqliteKevRepository
from vulntrack.infrastructure.persistence.repositories.project_repo import SqliteProjectRepository
from vulntrack.infrastructure.persistence.repositories.remediation_repo import (
    SqliteRemediationRepository,
)
from vulntrack.infrastructure.persistence.repositories.snapshot_repo import (
    SqliteSnapshotRepository,
)

NOW = datetime(2026, 6, 24, 12, 0, 0)
TODAY = date(2026, 6, 24)


def make_project(uuid: str = "proj-001", name: str = "Alpha") -> Project:
    return Project(
        uuid=uuid,
        name=name,
        version="1.0",
        description=None,
        last_bom_import=None,
        last_synced_at=NOW,
    )


def make_snapshot(
    project_uuid: str = "proj-001",
    snap_date: date = TODAY,
    critical: int = 5,
    source: SnapshotSource = SnapshotSource.DT_CURRENT,
) -> MetricSnapshot:
    return MetricSnapshot(
        id=0,
        project_uuid=project_uuid,
        snapshot_date=snap_date,
        critical=critical,
        high=10,
        medium=15,
        low=3,
        unassigned=0,
        total=critical + 10 + 15 + 3,
        risk_score=7.5,
        source=source,
    )


def make_finding(
    project_uuid: str = "proj-001",
    dt_uuid: str = "dt-uuid-001",
    vuln_id: str = "CVE-2021-44228",
    severity: Severity = Severity.CRITICAL,
    attributed_on: datetime = NOW,
    cve_id: str | None = None,
    cvss_v3_base_score: float | None = 10.0,
    epss_score: float | None = 0.97,
) -> Finding:
    return Finding(
        id=0,
        project_uuid=project_uuid,
        dt_finding_uuid=dt_uuid,
        component_name="log4j",
        component_version="2.14.1",
        component_group=None,
        vuln_id=vuln_id,
        vuln_source="NVD",
        severity=severity,
        cvss_v3_base_score=cvss_v3_base_score,
        epss_score=epss_score,
        epss_percentile=0.999,
        attributed_on=attributed_on,
        suppressed=False,
        last_synced_at=NOW,
        cve_id=cve_id,
    )


def make_kev(cve_id: str = "CVE-2021-44228") -> KevEntry:
    return KevEntry(
        cve_id=cve_id,
        vendor_project="Apache",
        product="Log4j",
        vulnerability_name="Log4Shell",
        date_added=date(2021, 12, 10),
        short_description="RCE vulnerability",
        required_action="Apply update",
        due_date=date(2021, 12, 24),
        notes=None,
    )


# ── Project Repository ──────────────────────────────────────────────────────


class TestProjectRepository:
    async def test_upsert_and_get(self, db_session: AsyncSession) -> None:
        repo = SqliteProjectRepository(db_session)
        p = make_project()
        await repo.upsert(p)
        await db_session.flush()

        found = await repo.get_by_uuid("proj-001")
        assert found is not None
        assert found.name == "Alpha"

    async def test_upsert_idempotent(self, db_session: AsyncSession) -> None:
        repo = SqliteProjectRepository(db_session)
        p = make_project()
        await repo.upsert(p)
        await repo.upsert(p)
        await db_session.flush()

        count = await repo.count()
        assert count == 1

    async def test_upsert_updates_name(self, db_session: AsyncSession) -> None:
        repo = SqliteProjectRepository(db_session)
        await repo.upsert(make_project(name="Alpha"))
        await db_session.flush()
        await repo.upsert(make_project(name="Beta"))
        await db_session.flush()

        found = await repo.get_by_uuid("proj-001")
        assert found is not None
        assert found.name == "Beta"

    async def test_get_by_uuid_not_found(self, db_session: AsyncSession) -> None:
        repo = SqliteProjectRepository(db_session)
        assert await repo.get_by_uuid("nonexistent") is None

    async def test_list_all_ordered_by_name(self, db_session: AsyncSession) -> None:
        repo = SqliteProjectRepository(db_session)
        await repo.upsert(make_project(uuid="p2", name="Zeta"))
        await repo.upsert(make_project(uuid="p1", name="Alpha"))
        await db_session.flush()

        projects = await repo.list_all()
        assert [p.name for p in projects] == ["Alpha", "Zeta"]

    async def test_count(self, db_session: AsyncSession) -> None:
        repo = SqliteProjectRepository(db_session)
        assert await repo.count() == 0
        await repo.upsert(make_project(uuid="p1", name="A"))
        await repo.upsert(make_project(uuid="p2", name="B"))
        await db_session.flush()
        assert await repo.count() == 2


# ── Finding Repository ──────────────────────────────────────────────────────


class TestFindingRepository:
    async def _setup_project(self, db_session: AsyncSession) -> None:
        repo = SqliteProjectRepository(db_session)
        await repo.upsert(make_project())
        await db_session.flush()

    async def test_upsert_batch(self, db_session: AsyncSession) -> None:
        await self._setup_project(db_session)
        repo = SqliteFindingRepository(db_session)
        findings = [make_finding(dt_uuid=f"uuid-{i:03d}") for i in range(5)]
        await repo.upsert_batch(findings)
        await db_session.flush()

        result = await repo.list_all_active()
        assert len(result) == 5

    async def test_upsert_batch_idempotent(self, db_session: AsyncSession) -> None:
        await self._setup_project(db_session)
        repo = SqliteFindingRepository(db_session)
        f = make_finding()
        await repo.upsert_batch([f])
        await repo.upsert_batch([f])
        await db_session.flush()

        result = await repo.list_all_active()
        assert len(result) == 1

    async def test_list_by_project(self, db_session: AsyncSession) -> None:
        repo_p = SqliteProjectRepository(db_session)
        await repo_p.upsert(make_project(uuid="p1"))
        await repo_p.upsert(make_project(uuid="p2", name="Beta"))
        await db_session.flush()

        repo = SqliteFindingRepository(db_session)
        await repo.upsert_batch([make_finding(project_uuid="p1", dt_uuid="f1")])
        await repo.upsert_batch([make_finding(project_uuid="p2", dt_uuid="f2")])
        await db_session.flush()

        result = await repo.list_by_project("p1")
        assert len(result) == 1
        assert result[0].project_uuid == "p1"

    async def test_get_new_in_range(self, db_session: AsyncSession) -> None:
        await self._setup_project(db_session)
        repo = SqliteFindingRepository(db_session)

        inside = make_finding(dt_uuid="f-in", attributed_on=datetime(2026, 4, 15, 0, 0, 0))
        outside = make_finding(dt_uuid="f-out", attributed_on=datetime(2026, 3, 1, 0, 0, 0))
        await repo.upsert_batch([inside, outside])
        await db_session.flush()

        result = await repo.get_new_in_range(date(2026, 4, 1), date(2026, 6, 30))
        assert len(result) == 1
        assert result[0].dt_finding_uuid == "f-in"

    async def test_upsert_large_batch(self, db_session: AsyncSession) -> None:
        await self._setup_project(db_session)
        repo = SqliteFindingRepository(db_session)
        findings = [
            make_finding(dt_uuid=f"uuid-{i:04d}", vuln_id=f"CVE-2026-{i:04d}")
            for i in range(100)
        ]
        await repo.upsert_batch(findings)
        await db_session.flush()

        result = await repo.list_all_active()
        assert len(result) == 100

    async def test_upsert_stores_cve_id(self, db_session: AsyncSession) -> None:
        await self._setup_project(db_session)
        repo = SqliteFindingRepository(db_session)
        await repo.upsert_batch([make_finding(vuln_id="GHSA-xxxx", cve_id="CVE-2024-1")])
        await db_session.flush()

        result = await repo.list_all_active()
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2024-1"

    async def test_upsert_updates_cve_id_on_conflict(self, db_session: AsyncSession) -> None:
        await self._setup_project(db_session)
        repo = SqliteFindingRepository(db_session)
        await repo.upsert_batch([make_finding(cve_id=None)])
        await db_session.flush()
        await repo.upsert_batch([make_finding(cve_id="CVE-2021-44228")])
        await db_session.flush()

        result = await repo.list_all_active()
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2021-44228"

    async def test_list_all_active_min_cvss_filter(self, db_session: AsyncSession) -> None:
        await self._setup_project(db_session)
        repo = SqliteFindingRepository(db_session)
        await repo.upsert_batch([
            make_finding(dt_uuid="high", cvss_v3_base_score=9.0),
            make_finding(dt_uuid="low", cvss_v3_base_score=3.0),
            make_finding(dt_uuid="null-score", cvss_v3_base_score=None),
        ])
        await db_session.flush()

        result = await repo.list_all_active(min_cvss=7.0)
        assert [r.dt_finding_uuid for r in result] == ["high"]


# ── Snapshot Repository ─────────────────────────────────────────────────────


class TestSnapshotRepository:
    async def _setup_project(self, db_session: AsyncSession) -> None:
        repo = SqliteProjectRepository(db_session)
        await repo.upsert(make_project())
        await db_session.flush()

    async def test_upsert_and_get_closest_before(self, db_session: AsyncSession) -> None:
        await self._setup_project(db_session)
        repo = SqliteSnapshotRepository(db_session)

        dates = [date(2026, 4, 1), date(2026, 5, 1), date(2026, 6, 1)]
        for d in dates:
            await repo.upsert(make_snapshot(snap_date=d))
        await db_session.flush()

        result = await repo.get_closest_before("proj-001", date(2026, 5, 15))
        assert result is not None
        assert result.snapshot_date == date(2026, 5, 1)

    async def test_get_closest_before_none(self, db_session: AsyncSession) -> None:
        await self._setup_project(db_session)
        repo = SqliteSnapshotRepository(db_session)
        result = await repo.get_closest_before("proj-001", date(2026, 1, 1))
        assert result is None

    async def test_get_closest_after(self, db_session: AsyncSession) -> None:
        await self._setup_project(db_session)
        repo = SqliteSnapshotRepository(db_session)

        for d in [date(2026, 4, 1), date(2026, 5, 1), date(2026, 6, 1)]:
            await repo.upsert(make_snapshot(snap_date=d))
        await db_session.flush()

        result = await repo.get_closest_after("proj-001", date(2026, 4, 15))
        assert result is not None
        assert result.snapshot_date == date(2026, 5, 1)

    async def test_upsert_idempotent(self, db_session: AsyncSession) -> None:
        await self._setup_project(db_session)
        repo = SqliteSnapshotRepository(db_session)
        s = make_snapshot()
        await repo.upsert(s)
        await repo.upsert(s)
        await db_session.flush()

        result = await repo.list_by_project_in_range("proj-001", TODAY, TODAY)
        assert len(result) == 1

    async def test_count_by_source(self, db_session: AsyncSession) -> None:
        await self._setup_project(db_session)
        repo = SqliteSnapshotRepository(db_session)
        await repo.upsert(
            make_snapshot(snap_date=date(2026, 4, 1), source=SnapshotSource.DT_HISTORICAL)
        )
        await repo.upsert(
            make_snapshot(snap_date=date(2026, 5, 1), source=SnapshotSource.DT_CURRENT)
        )
        await db_session.flush()

        assert await repo.count_by_source("DT_HISTORICAL") == 1
        assert await repo.count_by_source("DT_CURRENT") == 1


# ── KEV Repository ──────────────────────────────────────────────────────────


class TestKevRepository:
    async def test_upsert_batch_and_list(self, db_session: AsyncSession) -> None:
        repo = SqliteKevRepository(db_session)
        entries = [make_kev(f"CVE-2024-{i:04d}") for i in range(5)]
        await repo.upsert_batch(entries)
        await db_session.flush()

        result = await repo.list_all()
        assert len(result) == 5

    async def test_get_by_cve_id(self, db_session: AsyncSession) -> None:
        repo = SqliteKevRepository(db_session)
        await repo.upsert_batch([make_kev()])
        await db_session.flush()

        found = await repo.get_by_cve_id("CVE-2021-44228")
        assert found is not None
        assert found.cve_id == "CVE-2021-44228"

    async def test_is_cve_in_kev_true(self, db_session: AsyncSession) -> None:
        repo = SqliteKevRepository(db_session)
        await repo.upsert_batch([make_kev()])
        await db_session.flush()

        assert await repo.is_cve_in_kev("CVE-2021-44228") is True

    async def test_is_cve_in_kev_false(self, db_session: AsyncSession) -> None:
        repo = SqliteKevRepository(db_session)
        assert await repo.is_cve_in_kev("CVE-9999-9999") is False

    async def test_get_catalog_meta_returns_aware_datetime(self, db_session: AsyncSession) -> None:
        repo = SqliteKevRepository(db_session)
        await repo.upsert_batch([make_kev()])
        await db_session.flush()

        meta = await repo.get_catalog_meta()
        assert meta is not None
        assert meta.last_fetched_at is not None
        assert meta.last_fetched_at.tzinfo is not None, "last_fetched_at debe ser UTC-aware"
        assert meta.catalog_updated_at.tzinfo is not None, "catalog_updated_at debe ser UTC-aware"
        # La resta contra datetime.now(UTC) no debe lanzar TypeError
        from datetime import timedelta
        age = datetime.now(UTC) - meta.last_fetched_at
        assert age < timedelta(minutes=1)

    async def test_get_catalog_meta_none_when_empty(self, db_session: AsyncSession) -> None:
        repo = SqliteKevRepository(db_session)
        assert await repo.get_catalog_meta() is None

    async def test_upsert_batch_updates(self, db_session: AsyncSession) -> None:
        repo = SqliteKevRepository(db_session)
        original = make_kev()
        await repo.upsert_batch([original])
        await db_session.flush()

        updated = KevEntry(
            cve_id="CVE-2021-44228",
            vendor_project="Apache Updated",
            product="Log4j",
            vulnerability_name="Log4Shell Updated",
            date_added=date(2021, 12, 10),
            short_description="Updated description",
            required_action="Patch now",
            due_date=None,
            notes="Updated note",
        )
        await repo.upsert_batch([updated])
        await db_session.flush()

        found = await repo.get_by_cve_id("CVE-2021-44228")
        assert found is not None
        assert found.vendor_project == "Apache Updated"

        result = await repo.list_all()
        assert len(result) == 1  # no duplicates


# ── Remediation Repository ──────────────────────────────────────────────────


class TestRemediationRepository:
    async def _setup_project(self, db_session: AsyncSession) -> None:
        repo = SqliteProjectRepository(db_session)
        await repo.upsert(make_project())
        await db_session.flush()

    async def test_create_and_get_plan(self, db_session: AsyncSession) -> None:
        await self._setup_project(db_session)
        repo = SqliteRemediationRepository(db_session)

        plan = await repo.create_plan("proj-001", "Q2 2026 Remediation", None)
        assert plan.id is not None
        assert plan.name == "Q2 2026 Remediation"

        found = await repo.get_plan(plan.id)
        assert found is not None
        assert found.project_uuid == "proj-001"

    async def test_list_plans_by_project(self, db_session: AsyncSession) -> None:
        await self._setup_project(db_session)
        repo = SqliteRemediationRepository(db_session)

        await repo.create_plan("proj-001", "Plan A", None)
        await repo.create_plan("proj-001", "Plan B", None)

        plans = await repo.list_plans_by_project("proj-001")
        assert len(plans) == 2

    async def test_create_task(self, db_session: AsyncSession) -> None:
        await self._setup_project(db_session)
        repo = SqliteRemediationRepository(db_session)

        plan = await repo.create_plan("proj-001", "Plan", None)
        task = await repo.create_task(
            plan.id,
            title="Fix CVE",
            priority_band=PriorityBand.CRITICAL,
            status=TaskStatus.PENDING,
        )
        assert task.id is not None
        assert task.title == "Fix CVE"
        assert task.status == TaskStatus.PENDING

    async def test_update_task(self, db_session: AsyncSession) -> None:
        await self._setup_project(db_session)
        repo = SqliteRemediationRepository(db_session)

        plan = await repo.create_plan("proj-001", "Plan", None)
        task = await repo.create_task(
            plan.id, title="Fix", priority_band=PriorityBand.HIGH
        )
        updated = await repo.update_task(task.id, status=TaskStatus.IN_PROGRESS, assignee="alice")
        assert updated.status == TaskStatus.IN_PROGRESS
        assert updated.assignee == "alice"

    async def test_list_tasks_by_plan(self, db_session: AsyncSession) -> None:
        await self._setup_project(db_session)
        repo = SqliteRemediationRepository(db_session)

        plan = await repo.create_plan("proj-001", "Plan", None)
        for i in range(3):
            await repo.create_task(plan.id, title=f"Task {i}", priority_band=PriorityBand.MEDIUM)

        tasks = await repo.list_tasks_by_plan(plan.id)
        assert len(tasks) == 3


# ── AppSettings Repository ──────────────────────────────────────────────────


class TestAppSettingsRepository:
    async def test_get_creates_defaults(self, db_session: AsyncSession) -> None:
        repo = SqliteAppSettingsRepository(db_session)
        settings = await repo.get()
        assert settings.id == 1
        assert settings.sync_interval_hours == 6
        assert settings.w_cvss_weight == 0.30

    async def test_get_idempotent(self, db_session: AsyncSession) -> None:
        repo = SqliteAppSettingsRepository(db_session)
        s1 = await repo.get()
        s2 = await repo.get()
        assert s1.id == s2.id == 1

    async def test_update(self, db_session: AsyncSession) -> None:
        repo = SqliteAppSettingsRepository(db_session)
        await repo.get()
        updated = await repo.update(sync_interval_hours=12, w_cvss_weight=0.50)
        assert updated.sync_interval_hours == 12
        assert updated.w_cvss_weight == 0.50

    async def test_update_persists(self, db_session: AsyncSession) -> None:
        repo = SqliteAppSettingsRepository(db_session)
        await repo.get()
        await repo.update(kev_stale_days=14)
        settings = await repo.get()
        assert settings.kev_stale_days == 14
