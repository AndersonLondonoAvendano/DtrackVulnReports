"""Tests para T-054: PdfGenerator.

WeasyPrint requiere GTK/Pango (disponibles en la imagen Docker de T-007).
En Windows nativo, los tests se saltan si las bibliotecas del sistema no están disponibles.
"""
from __future__ import annotations

from datetime import date, datetime

import pytest

from vulntrack.domain.value_objects.priority_score import PriorityBand
from vulntrack.domain.value_objects.severity import Severity
from vulntrack.infrastructure.reports.chart_builder import (
    EvolutionRow,
    PrioritizedFindingRow,
    ProjectRow,
    ReportData,
)

try:
    from vulntrack.infrastructure.reports.pdf_generator import PdfGenerator
    _WEASYPRINT_AVAILABLE = True
except OSError:
    _WEASYPRINT_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _WEASYPRINT_AVAILABLE,
    reason="WeasyPrint requiere GTK/Pango (disponible en Docker, no en Windows nativo)",
)


def _sample_data() -> ReportData:
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
        project_rows=[
            ProjectRow("daviplata-webview-frontend", 5, 10, 20, 15, 2, 52, 8.5),
            ProjectRow("backend-core", 2, 3, 8, 5, 0, 18, 4.2),
        ],
        evolution_rows=[
            EvolutionRow("daviplata-webview-frontend", 60, 52, -8, 8),
            EvolutionRow("backend-core", 14, 18, 4, 0),
        ],
        prioritized_findings=[
            PrioritizedFindingRow(
                vuln_id="CVE-2024-1234",
                component_name="log4j-core",
                component_version="2.14.0",
                project_name="daviplata-webview-frontend",
                severity=Severity.CRITICAL,
                cvss_v3_base_score=9.8,
                epss_score=0.85,
                is_kev=True,
                priority_score=92.5,
                priority_band=PriorityBand.CRITICAL,
            ),
        ],
        kev_hits=[
            PrioritizedFindingRow(
                vuln_id="CVE-2024-1234",
                component_name="log4j-core",
                component_version="2.14.0",
                project_name="daviplata-webview-frontend",
                severity=Severity.CRITICAL,
                cvss_v3_base_score=9.8,
                epss_score=0.85,
                is_kev=True,
                priority_score=92.5,
                priority_band=PriorityBand.CRITICAL,
            )
        ],
    )


class TestPdfGenerator:
    def setup_method(self) -> None:
        if _WEASYPRINT_AVAILABLE:
            self.generator = PdfGenerator()  # type: ignore[name-defined]
        self.data = _sample_data()

    def test_generate_returns_bytes(self) -> None:
        result = self.generator.generate(self.data)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_is_valid_pdf(self) -> None:
        result = self.generator.generate(self.data)
        # PDF files start with %PDF
        assert result[:4] == b"%PDF"

    def test_generate_with_empty_data(self) -> None:
        empty = ReportData(
            period_label="Q1 2026",
            date_from=date(2026, 1, 1),
            date_to=date(2026, 3, 31),
            generated_at=datetime(2026, 3, 31, 0, 0, 0),
            author="Test",
            total_vigentes=0,
            total_nuevas=0,
            total_tratadas=0,
            risk_score_portfolio=0.0,
        )
        result = self.generator.generate(empty)
        assert result[:4] == b"%PDF"

    def test_generate_with_no_kev(self) -> None:
        data = _sample_data()
        data.kev_hits = []
        result = self.generator.generate(data)
        assert result[:4] == b"%PDF"

    def test_generate_with_no_findings(self) -> None:
        data = _sample_data()
        data.prioritized_findings = []
        result = self.generator.generate(data)
        assert result[:4] == b"%PDF"

    def test_pdf_size_reasonable(self) -> None:
        result = self.generator.generate(self.data)
        # A PDF with charts should be at least 50KB
        assert len(result) > 50_000
