"""Tests de los modelos Pydantic de respuesta de DT API (T-041)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulntrack.infrastructure.dt.response_models import (
    DtAbout,
    DtFinding,
    DtMetrics,
    DtMetricsHistory,
    DtProject,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestDtProject:
    def test_parse_from_fixture(self) -> None:
        raw = json.loads((FIXTURES / "dt_project.json").read_text())
        project = DtProject.model_validate(raw)
        assert project.uuid == "f3a1b2c3-0000-4000-8000-000000000001"
        assert project.name == "Backend API"
        assert project.version == "2.1.0"
        assert project.description == "Servicio REST principal"
        assert project.last_bom_import is not None

    def test_optional_fields_default_none(self) -> None:
        project = DtProject.model_validate({"uuid": "abc", "name": "Test"})
        assert project.version is None
        assert project.description is None
        assert project.last_bom_import is None

    def test_camel_case_alias_lastBomImport(self) -> None:
        project = DtProject.model_validate({
            "uuid": "abc",
            "name": "Test",
            "lastBomImport": 1718000000000,
        })
        assert project.last_bom_import is not None

    def test_by_name_also_works(self) -> None:
        project = DtProject.model_validate({
            "uuid": "abc",
            "name": "Test",
            "last_bom_import": "2024-06-10T00:00:00",
        })
        assert project.last_bom_import is not None


class TestDtMetrics:
    def test_parse_from_fixture(self) -> None:
        raw = json.loads((FIXTURES / "dt_metrics.json").read_text())
        metrics = DtMetrics.model_validate(raw)
        assert metrics.critical == 3
        assert metrics.high == 12
        assert metrics.medium == 25
        assert metrics.low == 8
        assert metrics.unassigned == 1
        assert metrics.risk_score == pytest.approx(7.4)
        assert metrics.total == 49

    def test_defaults_are_zero(self) -> None:
        metrics = DtMetrics.model_validate({})
        assert metrics.critical == 0
        assert metrics.risk_score == 0.0
        assert metrics.total == 0

    def test_inherited_risk_score_alias(self) -> None:
        metrics = DtMetrics.model_validate({"inheritedRiskScore": 5.5})
        assert metrics.risk_score == pytest.approx(5.5)

    def test_vulnerabilities_alias_maps_to_total(self) -> None:
        metrics = DtMetrics.model_validate({"vulnerabilities": 99})
        assert metrics.total == 99

    def test_total_by_name_still_works(self) -> None:
        metrics = DtMetrics.model_validate({"total": 42})
        assert metrics.total == 42


class TestDtFinding:
    def test_parse_fixture_three_findings(self) -> None:
        raw = json.loads((FIXTURES / "dt_findings.json").read_text())
        findings = [DtFinding.model_validate(f) for f in raw]
        assert len(findings) == 3

    def test_first_finding_log4shell(self) -> None:
        raw = json.loads((FIXTURES / "dt_findings.json").read_text())
        f = DtFinding.model_validate(raw[0])
        assert f.component.name == "log4j-core"
        assert f.component.version == "2.14.1"
        assert f.component.group == "org.apache.logging.log4j"
        assert f.vulnerability.vuln_id == "CVE-2021-44228"
        assert f.vulnerability.severity == "CRITICAL"
        assert f.vulnerability.cvss_v3_base_score == pytest.approx(10.0)
        assert f.vulnerability.epss_score == pytest.approx(0.97)
        assert f.attribution is not None
        assert f.attribution.attributed_on is not None

    def test_second_finding_no_attribution(self) -> None:
        raw = json.loads((FIXTURES / "dt_findings.json").read_text())
        f = DtFinding.model_validate(raw[1])
        assert f.attribution is None
        assert f.matrix is None
        assert f.vulnerability.epss_score == pytest.approx(0.94)

    def test_third_finding_null_epss_and_purl(self) -> None:
        raw = json.loads((FIXTURES / "dt_findings.json").read_text())
        f = DtFinding.model_validate(raw[2])
        assert f.vulnerability.epss_score is None
        assert f.vulnerability.epss_percentile is None
        assert f.component.purl is None
        assert f.analysis is not None
        assert f.analysis.suppressed is True

    def test_vuln_id_alias(self) -> None:
        raw = {
            "component": {"name": "lib", "uuid": "x"},
            "vulnerability": {"vulnId": "CVE-2000-0001", "source": "NVD"},
        }
        f = DtFinding.model_validate(raw)
        assert f.vulnerability.vuln_id == "CVE-2000-0001"

    def test_default_severity_unassigned(self) -> None:
        raw = {
            "component": {"name": "lib", "uuid": "x"},
            "vulnerability": {"vulnId": "CVE-2000-0002"},
        }
        f = DtFinding.model_validate(raw)
        assert f.vulnerability.severity == "UNASSIGNED"


class TestDtFindingGhsaFixture:
    """Prueba el fixture de findings GHSA reales (isSuppressed + cvssV3Vector)."""

    def test_is_suppressed_alias(self) -> None:
        raw = {
            "component": {"name": "lib", "uuid": "x"},
            "vulnerability": {"vulnId": "GHSA-xxxx", "source": "GITHUB"},
            "analysis": {"state": "NOT_AFFECTED", "isSuppressed": True},
        }
        f = DtFinding.model_validate(raw)
        assert f.analysis is not None
        assert f.analysis.suppressed is True

    def test_is_suppressed_false(self) -> None:
        raw = {
            "component": {"name": "lib", "uuid": "x"},
            "vulnerability": {"vulnId": "GHSA-xxxx", "source": "GITHUB"},
            "analysis": {"state": "EXPLOITABLE", "isSuppressed": False},
        }
        f = DtFinding.model_validate(raw)
        assert f.analysis is not None
        assert f.analysis.suppressed is False

    def test_cvss_v3_vector_mapped(self) -> None:
        raw = {
            "component": {"name": "lib", "uuid": "x"},
            "vulnerability": {
                "vulnId": "GHSA-xxxx",
                "source": "GITHUB",
                "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            },
        }
        f = DtFinding.model_validate(raw)
        assert f.vulnerability.cvss_v3_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
        assert f.vulnerability.cvss_v3_base_score is None

    def test_cvss_v3_base_score_and_vector_coexist(self) -> None:
        raw = {
            "component": {"name": "lib", "uuid": "x"},
            "vulnerability": {
                "vulnId": "CVE-2021-44228",
                "source": "NVD",
                "cvssV3BaseScore": 10.0,
                "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            },
        }
        f = DtFinding.model_validate(raw)
        assert f.vulnerability.cvss_v3_base_score == 10.0
        assert f.vulnerability.cvss_v3_vector is not None

    def test_adm_zip_fixture_cvss_v3_vector(self) -> None:
        raw = json.loads((FIXTURES / "dt_finding_ghsa_with_cve_alias.json").read_text())
        f = DtFinding.model_validate(raw[0])
        assert f.component.name == "adm-zip"
        assert f.vulnerability.cvss_v3_vector == "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"
        assert f.vulnerability.cvss_v3_base_score is None


class TestDtMetricsHistory:
    def test_parse_history_entry(self) -> None:
        raw = {
            "critical": 1,
            "high": 4,
            "medium": 10,
            "low": 2,
            "unassigned": 0,
            "inheritedRiskScore": 3.2,
            "total": 17,
            "firstOccurrence": 1710000000000,
            "lastOccurrence": 1718000000000,
        }
        h = DtMetricsHistory.model_validate(raw)
        assert h.critical == 1
        assert h.total == 17
        assert h.risk_score == pytest.approx(3.2)

    def test_empty_history_entry_defaults(self) -> None:
        h = DtMetricsHistory.model_validate({})
        assert h.total == 0
        assert h.risk_score == 0.0

    def test_vulnerabilities_alias_maps_to_total(self) -> None:
        h = DtMetricsHistory.model_validate({"vulnerabilities": 42})
        assert h.total == 42


class TestDtAbout:
    def test_parse_about(self) -> None:
        raw = {
            "version": "4.14.1",
            "uuid": "server-uuid-001",
            "application": "Dependency-Track",
            "timestamp": "2024-06-10T00:00:00Z",
        }
        about = DtAbout.model_validate(raw)
        assert about.version == "4.14.1"
        assert about.application == "Dependency-Track"

    def test_empty_about_defaults(self) -> None:
        about = DtAbout.model_validate({})
        assert about.version == ""
        assert about.uuid is None
