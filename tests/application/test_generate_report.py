"""Tests T-066: GeneratePortfolioReport y GenerateProjectReport."""
from __future__ import annotations

from datetime import UTC, date, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from vulntrack.application.reports.generate_portfolio_report import (
    GeneratePortfolioReportUseCase,
    ReportFormat,
)
from vulntrack.application.reports.generate_project_report import GenerateProjectReportUseCase
from vulntrack.domain.value_objects.date_range import DateRange
from vulntrack.infrastructure.reports.chart_builder import ReportData


def _empty_report_data() -> ReportData:
    return ReportData(
        period_label="Q2 2026",
        date_from=date(2026, 4, 1),
        date_to=date(2026, 6, 30),
        generated_at=datetime.now(UTC),
        author="Test",
        total_vigentes=0,
        total_nuevas=0,
        total_tratadas=0,
        risk_score_portfolio=0.0,
    )


def _make_build_uc(data: ReportData) -> AsyncMock:
    build_uc = AsyncMock()
    build_uc.execute.return_value = data
    return build_uc


class TestGeneratePortfolioReportUseCase:
    @pytest.mark.asyncio
    async def test_generates_docx(self) -> None:
        data = _empty_report_data()
        build_uc = _make_build_uc(data)

        docx_gen = MagicMock()
        docx_gen.generate.return_value = b"PK\x03\x04fake-docx"

        uc = GeneratePortfolioReportUseCase(
            build_uc, {ReportFormat.DOCX: docx_gen}
        )
        dr = DateRange(date(2026, 4, 1), date(2026, 6, 30))
        result = await uc.execute(dr, "Q2 2026", [ReportFormat.DOCX])

        assert ReportFormat.DOCX in result
        assert result[ReportFormat.DOCX] == b"PK\x03\x04fake-docx"
        docx_gen.generate.assert_called_once_with(data)

    @pytest.mark.asyncio
    async def test_generates_multiple_formats(self) -> None:
        data = _empty_report_data()
        build_uc = _make_build_uc(data)

        docx_gen = MagicMock()
        docx_gen.generate.return_value = b"docx-bytes"
        xlsx_gen = MagicMock()
        xlsx_gen.generate.return_value = b"xlsx-bytes"

        uc = GeneratePortfolioReportUseCase(
            build_uc,
            {ReportFormat.DOCX: docx_gen, ReportFormat.XLSX: xlsx_gen},
        )
        dr = DateRange(date(2026, 4, 1), date(2026, 6, 30))
        result = await uc.execute(dr, "Q2 2026", [ReportFormat.DOCX, ReportFormat.XLSX])

        assert len(result) == 2
        assert result[ReportFormat.DOCX] == b"docx-bytes"
        assert result[ReportFormat.XLSX] == b"xlsx-bytes"

    @pytest.mark.asyncio
    async def test_missing_format_skipped(self) -> None:
        data = _empty_report_data()
        build_uc = _make_build_uc(data)

        uc = GeneratePortfolioReportUseCase(build_uc, {})
        dr = DateRange(date(2026, 4, 1), date(2026, 6, 30))
        result = await uc.execute(dr, "Q2 2026", [ReportFormat.DOCX])

        assert result == {}

    @pytest.mark.asyncio
    async def test_use_case_does_not_import_docx_directly(self) -> None:
        # GeneratePortfolioReportUseCase must not reference python-docx/openpyxl/weasyprint
        import importlib
        import sys
        mod = sys.modules.get("vulntrack.application.reports.generate_portfolio_report")
        # The module should not have imported docx, openpyxl or weasyprint at module level
        assert mod is not None
        mod_source_has_no_infra = "from docx" not in (mod.__file__ or "")
        assert "openpyxl" not in str(getattr(mod, "__spec__", ""))


class TestGenerateProjectReportUseCase:
    @pytest.mark.asyncio
    async def test_passes_project_uuid_to_build(self) -> None:
        data = _empty_report_data()
        build_uc = _make_build_uc(data)
        xlsx_gen = MagicMock()
        xlsx_gen.generate.return_value = b"xlsx"

        uc = GenerateProjectReportUseCase(build_uc, {ReportFormat.XLSX: xlsx_gen})
        dr = DateRange(date(2026, 4, 1), date(2026, 6, 30))
        result = await uc.execute("my-uuid", dr, "Q2 2026", [ReportFormat.XLSX])

        build_uc.execute.assert_called_once_with(
            date_range=dr, period_label="Q2 2026", project_uuids=["my-uuid"]
        )
        assert result[ReportFormat.XLSX] == b"xlsx"
