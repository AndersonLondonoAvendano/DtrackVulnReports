from datetime import date, datetime

from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.kev_entry import KevEntry
from vulntrack.domain.entities.metric_snapshot import MetricSnapshot, SnapshotSource
from vulntrack.domain.entities.project import Project
from vulntrack.domain.entities.remediation import RemediationTask, TaskStatus
from vulntrack.domain.value_objects.priority_score import PriorityBand
from vulntrack.domain.value_objects.severity import Severity

NOW = datetime(2026, 6, 24, 12, 0, 0)
TODAY = date(2026, 6, 24)


def make_project(**kwargs: object) -> Project:
    defaults: dict[str, object] = {
        "uuid": "proj-001",
        "name": "Test Project",
        "version": "1.0",
        "description": None,
        "last_bom_import": None,
        "last_synced_at": NOW,
    }
    defaults.update(kwargs)
    return Project(**defaults)  # type: ignore[arg-type]


def make_snapshot(**kwargs: object) -> MetricSnapshot:
    defaults: dict[str, object] = {
        "id": 1,
        "project_uuid": "proj-001",
        "snapshot_date": TODAY,
        "critical": 5,
        "high": 10,
        "medium": 20,
        "low": 8,
        "unassigned": 2,
        "total": 45,
        "risk_score": 7.5,
        "source": SnapshotSource.DT_CURRENT,
    }
    defaults.update(kwargs)
    return MetricSnapshot(**defaults)  # type: ignore[arg-type]


def make_finding(**kwargs: object) -> Finding:
    defaults: dict[str, object] = {
        "id": 1,
        "project_uuid": "proj-001",
        "dt_finding_uuid": "dt-uuid-001",
        "component_name": "log4j",
        "component_version": "2.14.1",
        "component_group": "org.apache",
        "vuln_id": "CVE-2021-44228",
        "vuln_source": "NVD",
        "severity": Severity.CRITICAL,
        "cvss_v3_base_score": 10.0,
        "epss_score": 0.97,
        "epss_percentile": 0.999,
        "attributed_on": NOW,
        "suppressed": False,
        "last_synced_at": NOW,
    }
    defaults.update(kwargs)
    return Finding(**defaults)  # type: ignore[arg-type]


def make_task(**kwargs: object) -> RemediationTask:
    defaults: dict[str, object] = {
        "id": 1,
        "plan_id": 1,
        "finding_id": None,
        "title": "Fix CVE",
        "description": None,
        "assignee": None,
        "status": TaskStatus.PENDING,
        "priority_band": PriorityBand.IMMEDIATE,
        "recommended_action": None,
        "target_date": None,
        "completed_at": None,
        "notes": None,
        "created_at": NOW,
        "updated_at": NOW,
    }
    defaults.update(kwargs)
    return RemediationTask(**defaults)  # type: ignore[arg-type]


class TestProject:
    def test_instantiation(self) -> None:
        p = make_project()
        assert p.uuid == "proj-001"
        assert p.version == "1.0"

    def test_no_external_imports(self) -> None:
        import vulntrack.domain.entities.project as mod
        src = mod.__file__ or ""
        # Ensure no SQLAlchemy or FastAPI imports in the module
        assert "sqlalchemy" not in src
        assert "fastapi" not in src


class TestMetricSnapshot:
    def test_total_assigned(self) -> None:
        s = make_snapshot(critical=5, high=10, medium=20, low=8, unassigned=2)
        assert s.total_assigned() == 43  # excludes unassigned

    def test_total_assigned_all_zero(self) -> None:
        s = make_snapshot(critical=0, high=0, medium=0, low=0, unassigned=5)
        assert s.total_assigned() == 0


class TestFinding:
    def test_normalized_cvss_full(self) -> None:
        f = make_finding(cvss_v3_base_score=10.0)
        assert f.normalized_cvss() == 1.0

    def test_normalized_cvss_none(self) -> None:
        f = make_finding(cvss_v3_base_score=None)
        assert f.normalized_cvss() == 0.0

    def test_normalized_cvss_partial(self) -> None:
        f = make_finding(cvss_v3_base_score=5.0)
        assert f.normalized_cvss() == 0.5

    def test_safe_epss_present(self) -> None:
        f = make_finding(epss_score=0.85)
        assert f.safe_epss() == 0.85

    def test_safe_epss_none(self) -> None:
        f = make_finding(epss_score=None)
        assert f.safe_epss() == 0.0


class TestKevEntry:
    def test_instantiation(self) -> None:
        k = KevEntry(
            cve_id="CVE-2021-44228",
            vendor_project="Apache",
            product="Log4j",
            vulnerability_name="Log4Shell",
            date_added=date(2021, 12, 10),
            short_description="RCE in Log4j",
            required_action="Apply patch",
            due_date=date(2021, 12, 24),
            notes=None,
        )
        assert k.cve_id == "CVE-2021-44228"
        assert k.due_date == date(2021, 12, 24)


class TestRemediationTask:
    def test_is_overdue_past_date(self) -> None:
        task = make_task(target_date=date(2026, 6, 1), status=TaskStatus.PENDING)
        assert task.is_overdue(TODAY) is True

    def test_is_overdue_future_date(self) -> None:
        task = make_task(target_date=date(2026, 12, 31), status=TaskStatus.PENDING)
        assert task.is_overdue(TODAY) is False

    def test_is_overdue_no_target_date(self) -> None:
        task = make_task(target_date=None)
        assert task.is_overdue(TODAY) is False

    def test_is_overdue_completed_not_overdue(self) -> None:
        task = make_task(target_date=date(2026, 1, 1), status=TaskStatus.COMPLETED)
        assert task.is_overdue(TODAY) is False

    def test_is_overdue_discarded_not_overdue(self) -> None:
        task = make_task(target_date=date(2026, 1, 1), status=TaskStatus.DISCARDED)
        assert task.is_overdue(TODAY) is False

    def test_is_overdue_same_day_not_overdue(self) -> None:
        task = make_task(target_date=TODAY, status=TaskStatus.IN_PROGRESS)
        assert task.is_overdue(TODAY) is False
