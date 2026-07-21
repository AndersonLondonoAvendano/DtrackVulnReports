from dataclasses import dataclass

from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.value_objects.priority_score import PriorityBand, PriorityScore
from vulntrack.domain.value_objects.severity import Severity


@dataclass(frozen=True)
class PriorityWeights:
    w_cvss: float = 0.45
    w_epss: float = 0.25
    w_kev: float = 0.30
    kev_minimum_score: float = 0.75
    # Piso: una severidad CRITICAL/HIGH nunca debe "camuflarse" en una banda
    # baja solo porque el EPSS todavía no refleja explotación activa.
    critical_severity_floor: float = 0.50
    high_severity_floor: float = 0.25
    # Techo sin KEV: la banda CRITICAL queda reservada para explotación
    # confirmada (catálogo CISA KEV); sin KEV el máximo posible es HIGH.
    non_kev_score_cap: float = 0.749


class PrioritizationService:
    def __init__(self, weights: PriorityWeights | None = None) -> None:
        self.weights = weights or PriorityWeights()

    def score(self, finding: Finding, is_in_kev: bool) -> PriorityScore:
        cvss_n = finding.normalized_cvss()
        epss = finding.safe_epss()
        kev_val = 1.0 if is_in_kev else 0.0

        raw = (
            cvss_n * self.weights.w_cvss
            + epss * self.weights.w_epss
            + kev_val * self.weights.w_kev
        )

        clamped = min(max(raw, 0.0), 1.0)
        if is_in_kev:
            clamped = max(clamped, self.weights.kev_minimum_score)
        else:
            if finding.severity == Severity.CRITICAL:
                clamped = max(clamped, self.weights.critical_severity_floor)
            elif finding.severity == Severity.HIGH:
                clamped = max(clamped, self.weights.high_severity_floor)
            clamped = min(clamped, self.weights.non_kev_score_cap)

        value = round(clamped * 100, 1)
        band = PriorityBand.from_value(value)

        breakdown = {
            "cvss": round(cvss_n * self.weights.w_cvss * 100, 2),
            "epss": round(epss * self.weights.w_epss * 100, 2),
            "kev": round(kev_val * self.weights.w_kev * 100, 2),
        }

        return PriorityScore(value=value, band=band, is_kev=is_in_kev, breakdown=breakdown)
