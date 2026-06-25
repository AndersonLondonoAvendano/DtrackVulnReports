from datetime import date, datetime

import pytest

from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.metric_snapshot import MetricSnapshot, SnapshotSource
from vulntrack.domain.entities.project import Project
from vulntrack.domain.exceptions import SnapshotNotAvailableError
from vulntrack.domain.services.advance_calculator import AdvanceCalculator
from vulntrack.domain.value_objects.severity import Severity

NOW = datetime(2026, 6, 24, 12, 0, 0)
TODAY = date(2026, 6, 24)
START_DATE = date(2026, 4, 1)


def make_project() -> Project:
    return Project(
        uuid="proj-001",
        name="Test",
        version=None,
        description=None,
        last_bom_import=None,
        last_synced_at=NOW,
    )


def make_snapshot(
    total: int,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    snap_date: date = TODAY,
) -> MetricSnapshot:
    unassigned = max(0, total - critical - high - medium - low)
    return MetricSnapshot(
        id=1,
        project_uuid="proj-001",
        snapshot_date=snap_date,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        unassigned=unassigned,
        total=total,
        risk_score=5.0,
        source=SnapshotSource.DT_CURRENT,
    )


def make_finding(severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=1,
        project_uuid="proj-001",
        dt_finding_uuid="dt-uuid-001",
        component_name="lib",
        component_version=None,
        component_group=None,
        vuln_id="CVE-2026-0001",
        vuln_source="NVD",
        severity=severity,
        cvss_v3_base_score=None,
        epss_score=None,
        epss_percentile=None,
        attributed_on=NOW,
        suppressed=False,
        last_synced_at=NOW,
    )


class TestAdvanceCalculator:
    def setup_method(self) -> None:
        self.calc = AdvanceCalculator()
        self.project = make_project()

    def test_improvement(self) -> None:
        # inicio=20 total, actual=8 → tratadas=12, variacion=-12
        inicio = make_snapshot(total=20, critical=5, high=5, medium=5, low=5)
        actual = make_snapshot(total=8, critical=2, high=2, medium=2, low=2)
        result = self.calc.calculate(self.project, inicio, actual, [])
        assert result.variacion_total == -12
        assert result.tratadas == 12

    def test_regression(self) -> None:
        # inicio=5, actual=11 → tratadas=0, variacion=+6
        inicio = make_snapshot(total=5, high=5)
        actual = make_snapshot(total=11, high=11)
        result = self.calc.calculate(self.project, inicio, actual, [])
        assert result.variacion_total == 6
        assert result.tratadas == 0

    def test_no_change(self) -> None:
        inicio = make_snapshot(total=10, critical=10)
        actual = make_snapshot(total=10, critical=10)
        result = self.calc.calculate(self.project, inicio, actual, [])
        assert result.variacion_total == 0
        assert result.tratadas == 0

    def test_no_inicio_snapshot_raises(self) -> None:
        with pytest.raises(SnapshotNotAvailableError):
            self.calc.calculate(self.project, None, make_snapshot(total=5), [])

    def test_nuevas_por_severidad_counted(self) -> None:
        inicio = make_snapshot(total=10)
        actual = make_snapshot(total=10)
        new_findings = [
            make_finding(Severity.CRITICAL),
            make_finding(Severity.CRITICAL),
            make_finding(Severity.HIGH),
        ]
        result = self.calc.calculate(self.project, inicio, actual, new_findings)
        assert result.nuevas_por_severidad[Severity.CRITICAL] == 2
        assert result.nuevas_por_severidad[Severity.HIGH] == 1
        assert result.nuevas_por_severidad[Severity.MEDIUM] == 0

    def test_no_actual_snapshot(self) -> None:
        inicio = make_snapshot(total=15, critical=5, high=5, medium=3, low=2)
        result = self.calc.calculate(self.project, inicio, None, [])
        assert result.actual is None
        assert result.variacion_total == -15
        assert result.tratadas == 15
