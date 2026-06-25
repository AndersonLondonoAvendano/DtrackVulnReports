"""T-066: Caso de uso GenerateProjectReport — reporte filtrado por un proyecto."""
from __future__ import annotations

from vulntrack.application.reports.build_report_data import BuildReportDataUseCase
from vulntrack.application.reports.generate_portfolio_report import ReportFormat
from vulntrack.domain.ports.report_generator import ReportGenerator
from vulntrack.domain.value_objects.date_range import DateRange
from vulntrack.infrastructure.reports.chart_builder import ReportData


class GenerateProjectReportUseCase:
    def __init__(
        self,
        build_use_case: BuildReportDataUseCase,
        generators: dict[ReportFormat, ReportGenerator],
    ) -> None:
        self._build = build_use_case
        self._generators = generators

    async def execute(
        self,
        project_uuid: str,
        date_range: DateRange,
        period_label: str,
        formats: list[ReportFormat],
    ) -> dict[ReportFormat, bytes]:
        data: ReportData = await self._build.execute(
            date_range=date_range,
            period_label=period_label,
            project_uuids=[project_uuid],
        )
        return {
            fmt: self._generators[fmt].generate(data)
            for fmt in formats
            if fmt in self._generators
        }
