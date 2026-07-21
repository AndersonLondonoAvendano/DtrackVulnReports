import pytest

from vulntrack.domain.services.cvss_parser import parse_cvss_v3_base_score


class TestParseCvssV3BaseScore:
    def test_medium_vector(self) -> None:
        score = parse_cvss_v3_base_score(
            "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"
        )
        assert score == pytest.approx(5.5, abs=0.05)

    def test_high_vector(self) -> None:
        score = parse_cvss_v3_base_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
        )
        assert score == pytest.approx(7.5, abs=0.05)

    def test_critical_vector(self) -> None:
        score = parse_cvss_v3_base_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        assert score == pytest.approx(9.8, abs=0.05)

    def test_invalid_vector_returns_none(self) -> None:
        assert parse_cvss_v3_base_score("INVALID") is None

    def test_empty_string_returns_none(self) -> None:
        assert parse_cvss_v3_base_score("") is None

    def test_none_returns_none(self) -> None:
        assert parse_cvss_v3_base_score(None) is None
