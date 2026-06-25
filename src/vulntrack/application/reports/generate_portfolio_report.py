"""T-066: Caso de uso GeneratePortfolioReport."""
from __future__ import annotations

from enum import StrEnum

from vulntrack.application.reports.build_report_data import BuildReportDataUseCase
from vulntrack.domain.ports.report_generator import ReportGenerator
from vulntrack.domain.value_objects.date_range import DateRange
from vulntrack.domain.value_objects.report_period import ReportPeriod
from vulntrack.infrastructure.reports.chart_builder import ReportData


class ReportFormat(StrEnum):
    DOCX = "docx"
    XLSX = "xlsx"
    PDF = "pdf"


class GeneratePortfolioReportUseCase:
    def __init__(
        self,
        build_use_case: BuildReportDataUseCase,
        generators: dict[ReportFormat, ReportGenerator],
    ) -> None:
        self._build = build_use_case
        self._generators = generators

    async def execute(
        self,
        date_range: DateRange,
        period_label: str,
        formats: list[ReportFormat],
    ) -> dict[ReportFormat, bytes]:
        data: ReportData = await self._build.execute(
            date_range=date_range,
            period_label=period_label,
        )
        return {
            fmt: self._generators[fmt].generate(data)
            for fmt in formats
            if fmt in self._generators
        }
