from datetime import date

import pytest

from vulntrack.domain.exceptions import DomainError
from vulntrack.domain.value_objects.date_range import DateRange
from vulntrack.domain.value_objects.priority_score import PriorityBand, PriorityScore
from vulntrack.domain.value_objects.report_period import ReportPeriod
from vulntrack.domain.value_objects.severity import Severity


class TestSeverity:
    def test_weights(self) -> None:
        assert Severity.CRITICAL.weight() == 1.0
        assert Severity.HIGH.weight() == 0.75
        assert Severity.MEDIUM.weight() == 0.5
        assert Severity.LOW.weight() == 0.25
        assert Severity.UNASSIGNED.weight() == 0.1

    def test_color_hex(self) -> None:
        assert Severity.CRITICAL.color_hex() == "#C00000"
        assert Severity.HIGH.color_hex() == "#FF0000"
        assert Severity.MEDIUM.color_hex() == "#FF9900"
        assert Severity.LOW.color_hex() == "#FFFF00"
        assert Severity.UNASSIGNED.color_hex() == "#D9D9D9"

    def test_is_str_enum(self) -> None:
        assert Severity.CRITICAL == "CRITICAL"
        assert isinstance(Severity.HIGH, str)


class TestPriorityBand:
    def test_from_value_critical(self) -> None:
        assert PriorityBand.from_value(100.0) == PriorityBand.CRITICAL
        assert PriorityBand.from_value(75.0) == PriorityBand.CRITICAL

    def test_from_value_high(self) -> None:
        assert PriorityBand.from_value(74.9) == PriorityBand.HIGH
        assert PriorityBand.from_value(50.0) == PriorityBand.HIGH

    def test_from_value_medium(self) -> None:
        assert PriorityBand.from_value(49.9) == PriorityBand.MEDIUM
        assert PriorityBand.from_value(25.0) == PriorityBand.MEDIUM

    def test_from_value_low(self) -> None:
        assert PriorityBand.from_value(24.9) == PriorityBand.LOW
        assert PriorityBand.from_value(0.0) == PriorityBand.LOW


class TestPriorityScore:
    def test_valid_score(self) -> None:
        score = PriorityScore(value=85.0, band=PriorityBand.CRITICAL, is_kev=True, breakdown={})
        assert score.value == 85.0
        assert score.is_kev is True

    def test_score_zero(self) -> None:
        score = PriorityScore(value=0.0, band=PriorityBand.LOW, is_kev=False, breakdown={})
        assert score.value == 0.0

    def test_score_hundred(self) -> None:
        score = PriorityScore(value=100.0, band=PriorityBand.CRITICAL, is_kev=True, breakdown={})
        assert score.value == 100.0

    def test_invalid_score_raises(self) -> None:
        with pytest.raises(ValueError):
            PriorityScore(value=101.0, band=PriorityBand.CRITICAL, is_kev=False, breakdown={})

    def test_negative_score_raises(self) -> None:
        with pytest.raises(ValueError):
            PriorityScore(value=-1.0, band=PriorityBand.LOW, is_kev=False, breakdown={})

    def test_breakdown_stored(self) -> None:
        bd = {"cvss": 0.3, "epss": 0.4, "kev": 0.3}
        score = PriorityScore(value=50.0, band=PriorityBand.HIGH, is_kev=False, breakdown=bd)
        assert score.breakdown["cvss"] == 0.3

    def test_frozen(self) -> None:
        score = PriorityScore(value=50.0, band=PriorityBand.HIGH, is_kev=False, breakdown={})
        with pytest.raises((AttributeError, TypeError)):
            score.value = 99.0  # type: ignore[misc]


class TestDateRange:
    def test_valid_range(self) -> None:
        dr = DateRange(date(2026, 1, 1), date(2026, 3, 31))
        assert dr.days() == 89

    def test_same_day_valid(self) -> None:
        dr = DateRange(date(2026, 6, 1), date(2026, 6, 1))
        assert dr.days() == 0

    def test_invalid_range_raises(self) -> None:
        with pytest.raises(DomainError):
            DateRange(date(2026, 6, 30), date(2026, 6, 1))

    def test_frozen(self) -> None:
        dr = DateRange(date(2026, 1, 1), date(2026, 12, 31))
        with pytest.raises((AttributeError, TypeError)):
            dr.date_from = date(2025, 1, 1)  # type: ignore[misc]


class TestReportPeriod:
    def test_quarterly_q1(self) -> None:
        dr = ReportPeriod.resolve(ReportPeriod.QUARTERLY, year=2026, quarter="Q1")
        assert dr == DateRange(date(2026, 1, 1), date(2026, 3, 31))

    def test_quarterly_q2(self) -> None:
        dr = ReportPeriod.resolve(ReportPeriod.QUARTERLY, year=2026, quarter="Q2")
        assert dr == DateRange(date(2026, 4, 1), date(2026, 6, 30))

    def test_quarterly_q3(self) -> None:
        dr = ReportPeriod.resolve(ReportPeriod.QUARTERLY, year=2026, quarter="Q3")
        assert dr == DateRange(date(2026, 7, 1), date(2026, 9, 30))

    def test_quarterly_q4(self) -> None:
        dr = ReportPeriod.resolve(ReportPeriod.QUARTERLY, year=2026, quarter="Q4")
        assert dr == DateRange(date(2026, 10, 1), date(2026, 12, 31))

    def test_monthly(self) -> None:
        dr = ReportPeriod.resolve(ReportPeriod.MONTHLY, year=2026, month=2)
        assert dr == DateRange(date(2026, 2, 1), date(2026, 2, 28))

    def test_monthly_leap_year(self) -> None:
        dr = ReportPeriod.resolve(ReportPeriod.MONTHLY, year=2024, month=2)
        assert dr == DateRange(date(2024, 2, 1), date(2024, 2, 29))

    def test_weekly(self) -> None:
        dr = ReportPeriod.resolve(ReportPeriod.WEEKLY, date_from=date(2026, 6, 16))
        assert dr == DateRange(date(2026, 6, 16), date(2026, 6, 22))

    def test_custom(self) -> None:
        dr = ReportPeriod.resolve(
            ReportPeriod.CUSTOM,
            date_from=date(2026, 4, 1),
            date_to=date(2026, 6, 16),
        )
        assert dr == DateRange(date(2026, 4, 1), date(2026, 6, 16))

    def test_custom_missing_dates_raises(self) -> None:
        with pytest.raises(DomainError):
            ReportPeriod.resolve(ReportPeriod.CUSTOM)

    def test_quarterly_missing_year_raises(self) -> None:
        with pytest.raises(DomainError):
            ReportPeriod.resolve(ReportPeriod.QUARTERLY, quarter="Q2")

    def test_quarterly_invalid_quarter_raises(self) -> None:
        with pytest.raises(DomainError):
            ReportPeriod.resolve(ReportPeriod.QUARTERLY, year=2026, quarter="Q5")
