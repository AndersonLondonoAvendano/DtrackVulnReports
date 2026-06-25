from dataclasses import dataclass

from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.value_objects.priority_score import PriorityBand, PriorityScore


@dataclass(frozen=True)
class PriorityWeights:
    w_cvss: float = 0.30
    w_epss: float = 0.40
    w_kev: float = 0.30
    kev_minimum_score: float = 0.75


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

        value = round(clamped * 100, 1)
        band = PriorityBand.from_value(value)

        breakdown = {
            "cvss": round(cvss_n * self.weights.w_cvss * 100, 2),
            "epss": round(epss * self.weights.w_epss * 100, 2),
            "kev": round(kev_val * self.weights.w_kev * 100, 2),
        }

        return PriorityScore(value=value, band=band, is_kev=is_in_kev, breakdown=breakdown)
