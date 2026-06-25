import calendar
from datetime import date, timedelta
from enum import StrEnum

from vulntrack.domain.exceptions import DomainError
from vulntrack.domain.value_objects.date_range import DateRange


class ReportPeriod(StrEnum):
    WEEKLY = "WEEKLY"
    MONTHLY = "MONTHLY"
    QUARTERLY = "QUARTERLY"
    CUSTOM = "CUSTOM"

    @staticmethod
    def resolve(
        period: "ReportPeriod",
        year: int | None = None,
        quarter: str | None = None,
        month: int | None = None,
        date_from: date | None = None,
        date_to: date | None = None,
    ) -> DateRange:
        if period == ReportPeriod.CUSTOM:
            if date_from is None or date_to is None:
                raise DomainError("CUSTOM period requires date_from and date_to")
            return DateRange(date_from, date_to)

        if period == ReportPeriod.WEEKLY:
            if date_from is None:
                raise DomainError("WEEKLY requires date_from (start of week)")
            return DateRange(date_from, date_from + timedelta(days=6))

        if year is None:
            raise DomainError(f"{period} requires year")

        if period == ReportPeriod.QUARTERLY:
            if quarter is None:
                raise DomainError("QUARTERLY requires quarter (Q1|Q2|Q3|Q4)")
            quarter_map: dict[str, tuple[int, int, int, int]] = {
                "Q1": (1, 1, 3, 31),
                "Q2": (4, 1, 6, 30),
                "Q3": (7, 1, 9, 30),
                "Q4": (10, 1, 12, 31),
            }
            if quarter not in quarter_map:
                raise DomainError(f"Invalid quarter '{quarter}'. Expected Q1|Q2|Q3|Q4")
            m_from, d_from, m_to, d_to = quarter_map[quarter]
            return DateRange(date(year, m_from, d_from), date(year, m_to, d_to))

        if period == ReportPeriod.MONTHLY:
            if month is None:
                raise DomainError("MONTHLY requires month (1-12)")
            last_day = calendar.monthrange(year, month)[1]
            return DateRange(date(year, month, 1), date(year, month, last_day))

        raise DomainError(f"Unhandled period: {period}")
