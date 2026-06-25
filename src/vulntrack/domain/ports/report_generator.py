from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from vulntrack.infrastructure.reports.chart_builder import ReportData


class ReportGenerator(Protocol):
    def generate(self, data: "ReportData") -> bytes: ...
