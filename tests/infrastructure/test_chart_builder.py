"""Tests para T-051: ReportData, ProjectRow, EvolutionRow, ChartBuilder."""
from datetime import date, datetime

from vulntrack.domain.value_objects.priority_score import PriorityBand
from vulntrack.domain.value_objects.severity import Severity
from vulntrack.infrastructure.reports.chart_builder import (
    ChartBuilder,
    EvolutionRow,
    PrioritizedFindingRow,
    ProjectRow,
    ReportData,
)


def _sample_project_rows() -> list[ProjectRow]:
    return [
        ProjectRow("Proyecto A", 5, 10, 20, 15, 2, 52, 8.5),
        ProjectRow("Proyecto B", 2, 3, 8, 5, 0, 18, 4.2),
        ProjectRow("Proyecto C", 0, 0, 0, 0, 0, 0, 0.0),
    ]


def _sample_evolution_rows() -> list[EvolutionRow]:
    return [
        EvolutionRow("Proyecto A", inicio=60, actual=48, variacion=-12, tratadas=12),
        EvolutionRow("Proyecto B", inicio=18, actual=24, variacion=6, tratadas=0),
        EvolutionRow("Proyecto C", inicio=10, actual=10, variacion=0, tratadas=0),
    ]


def _sample_report_data() -> ReportData:
    return ReportData(
        period_label="Q2 2026",
        date_from=date(2026, 4, 1),
        date_to=date(2026, 6, 30),
        generated_at=datetime(2026, 6, 25, 10, 0, 0),
        author="Anderson Avendaño",
        total_vigentes=223,
        total_nuevas=118,
        total_tratadas=97,
        risk_score_portfolio=7.8,
        portfolio_metrics={
            Severity.CRITICAL: 12,
            Severity.HIGH: 45,
            Severity.MEDIUM: 98,
            Severity.LOW: 58,
            Severity.UNASSIGNED: 10,
        },
        new_portfolio_metrics={
            Severity.CRITICAL: 5,
            Severity.HIGH: 30,
            Severity.MEDIUM: 60,
            Severity.LOW: 23,
            Severity.UNASSIGNED: 0,
        },
        project_rows=_sample_project_rows(),
        evolution_rows=_sample_evolution_rows(),
        prioritized_findings=[
            PrioritizedFindingRow(
                vuln_id="CVE-2024-1234",
                component_name="log4j-core",
                component_version="2.14.0",
                project_name="Proyecto A",
                severity=Severity.CRITICAL,
                cvss_v3_base_score=9.8,
                epss_score=0.85,
                is_kev=True,
                priority_score=92.5,
                priority_band=PriorityBand.CRITICAL,
            )
        ],
        kev_hits=[],
    )


class TestReportData:
    def test_instantiation(self) -> None:
        rd = _sample_report_data()
        assert rd.total_vigentes == 223
        assert rd.total_nuevas == 118
        assert rd.total_tratadas == 97
        assert rd.period_label == "Q2 2026"

    def test_project_rows(self) -> None:
        rd = _sample_report_data()
        assert len(rd.project_rows) == 3
        assert rd.project_rows[0].name == "Proyecto A"
        assert rd.project_rows[0].total == 52

    def test_portfolio_metrics_all_severities(self) -> None:
        rd = _sample_report_data()
        assert set(rd.portfolio_metrics.keys()) == set(Severity)

    def test_evolution_rows(self) -> None:
        rows = _sample_evolution_rows()
        assert rows[0].tratadas == 12
        assert rows[1].tratadas == 0
        assert rows[1].variacion == 6


class TestChartBuilder:
    def setup_method(self) -> None:
        self.builder = ChartBuilder()
        self.counts = {
            Severity.CRITICAL: 12,
            Severity.HIGH: 45,
            Severity.MEDIUM: 98,
            Severity.LOW: 58,
            Severity.UNASSIGNED: 10,
        }
        self.project_rows = _sample_project_rows()
        self.evolution_rows = _sample_evolution_rows()

    def test_donut_returns_png_bytes(self) -> None:
        buf = self.builder.donut_by_severity(self.counts, "Vulnerabilidades vigentes")
        data = buf.read()
        assert len(data) > 0
        assert data[:4] == b"\x89PNG"

    def test_donut_with_all_zeros(self) -> None:
        zero_counts = dict.fromkeys(Severity, 0)
        buf = self.builder.donut_by_severity(zero_counts, "Sin vulnerabilidades")
        data = buf.read()
        assert len(data) > 0
        assert data[:4] == b"\x89PNG"

    def test_horizontal_bars_returns_png_bytes(self) -> None:
        buf = self.builder.horizontal_bars_by_project(
            self.project_rows, "Estado por proyecto"
        )
        data = buf.read()
        assert len(data) > 0
        assert data[:4] == b"\x89PNG"

    def test_horizontal_bars_with_zero_project(self) -> None:
        rows = [ProjectRow("Empty", 0, 0, 0, 0, 0, 0, 0.0)]
        buf = self.builder.horizontal_bars_by_project(rows, "Proyecto vacío")
        data = buf.read()
        assert len(data) > 0

    def test_horizontal_bars_empty_list(self) -> None:
        buf = self.builder.horizontal_bars_by_project([], "Sin proyectos")
        data = buf.read()
        assert len(data) > 0

    def test_divergent_bars_returns_png_bytes(self) -> None:
        buf = self.builder.divergent_bars_evolution(
            self.evolution_rows, "Evolución del período"
        )
        data = buf.read()
        assert len(data) > 0
        assert data[:4] == b"\x89PNG"

    def test_divergent_bars_empty_list(self) -> None:
        buf = self.builder.divergent_bars_evolution([], "Vacío")
        data = buf.read()
        assert len(data) > 0

    def test_grouped_bars_returns_png_bytes(self) -> None:
        buf = self.builder.grouped_bars_inicio_vs_actual(
            self.evolution_rows, "Inicio vs Actual"
        )
        data = buf.read()
        assert len(data) > 0
        assert data[:4] == b"\x89PNG"

    def test_grouped_bars_empty_list(self) -> None:
        buf = self.builder.grouped_bars_inicio_vs_actual([], "Vacío")
        data = buf.read()
        assert len(data) > 0
