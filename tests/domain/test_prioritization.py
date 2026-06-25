from datetime import datetime

from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.services.prioritization import PrioritizationService, PriorityWeights
from vulntrack.domain.value_objects.priority_score import PriorityBand
from vulntrack.domain.value_objects.severity import Severity

NOW = datetime(2026, 6, 24, 12, 0, 0)


def make_finding(
    cvss: float | None = None,
    epss: float | None = None,
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        id=1,
        project_uuid="proj-001",
        dt_finding_uuid="dt-uuid-001",
        component_name="test-lib",
        component_version="1.0",
        component_group=None,
        vuln_id="CVE-2021-00001",
        vuln_source="NVD",
        severity=severity,
        cvss_v3_base_score=cvss,
        epss_score=epss,
        epss_percentile=None,
        attributed_on=NOW,
        suppressed=False,
        last_synced_at=NOW,
    )


class TestPrioritizationService:
    def setup_method(self) -> None:
        self.svc = PrioritizationService()

    def test_kev_high_cvss_epss(self) -> None:
        # CVSS=9.8, EPSS=0.85, KEV=True
        # raw = (0.98*0.30) + (0.85*0.40) + (1.0*0.30) = 0.294+0.34+0.30 = 0.934
        # score = 93.4
        f = make_finding(cvss=9.8, epss=0.85)
        result = self.svc.score(f, is_in_kev=True)
        assert result.value == 93.4
        assert result.band == PriorityBand.IMMEDIATE
        assert result.is_kev is True

    def test_kev_low_cvss_epss_elevation(self) -> None:
        # CVSS=2.0, EPSS=0.01, KEV=True
        # raw = (0.20*0.30) + (0.01*0.40) + (1.0*0.30) = 0.06+0.004+0.30 = 0.364
        # clamp=0.364, but kev_min=0.75 → clamped=0.75 → score=75.0
        f = make_finding(cvss=2.0, epss=0.01)
        result = self.svc.score(f, is_in_kev=True)
        assert result.value == 75.0
        assert result.band == PriorityBand.IMMEDIATE

    def test_no_cvss_no_epss_no_kev(self) -> None:
        f = make_finding(cvss=None, epss=None)
        result = self.svc.score(f, is_in_kev=False)
        assert result.value == 0.0
        assert result.band == PriorityBand.LOW
        assert result.is_kev is False

    def test_epss_none_treated_as_zero(self) -> None:
        f_with_none = make_finding(cvss=5.0, epss=None)
        f_with_zero = make_finding(cvss=5.0, epss=0.0)
        assert self.svc.score(f_with_none, False).value == self.svc.score(f_with_zero, False).value

    def test_custom_weights(self) -> None:
        weights = PriorityWeights(w_cvss=0.50, w_epss=0.50, w_kev=0.0, kev_minimum_score=0.75)
        svc = PrioritizationService(weights)
        # CVSS=8.0, EPSS=0.6 → (0.8*0.5)+(0.6*0.5) = 0.4+0.3 = 0.70 → 70.0
        f = make_finding(cvss=8.0, epss=0.6)
        result = svc.score(f, is_in_kev=False)
        assert result.value == 70.0
        assert result.band == PriorityBand.HIGH

    def test_score_clamped_to_100(self) -> None:
        # Max CVSS, max EPSS, KEV → should not exceed 100
        f = make_finding(cvss=10.0, epss=1.0)
        result = self.svc.score(f, is_in_kev=True)
        assert result.value <= 100.0

    def test_breakdown_keys(self) -> None:
        f = make_finding(cvss=7.0, epss=0.5)
        result = self.svc.score(f, is_in_kev=False)
        assert "cvss" in result.breakdown
        assert "epss" in result.breakdown
        assert "kev" in result.breakdown

    def test_no_kev_no_elevation(self) -> None:
        # CVSS=2.0, EPSS=0.01, no KEV — should NOT be elevated to 75
        f = make_finding(cvss=2.0, epss=0.01)
        result = self.svc.score(f, is_in_kev=False)
        assert result.value < 75.0
