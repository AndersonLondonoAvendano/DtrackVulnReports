"""T-064: Query de hallazgos priorizados del portafolio completo."""
from __future__ import annotations

from dataclasses import dataclass

from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.ports.finding_repository import FindingRepository
from vulntrack.domain.services.kev_matcher import KevMatcher
from vulntrack.domain.services.prioritization import PrioritizationService, PriorityWeights
from vulntrack.domain.value_objects.priority_score import PriorityScore


@dataclass
class PrioritizedFindingItem:
    finding: Finding
    score: PriorityScore


class PrioritizedFindingsQuery:
    def __init__(
        self,
        finding_repo: FindingRepository,
        kev_matcher: KevMatcher,
        weights: PriorityWeights | None = None,
    ) -> None:
        self._finding_repo = finding_repo
        self._kev_matcher = kev_matcher
        self._svc = PrioritizationService(weights)

    async def execute(
        self,
        *,
        kev_only: bool = False,
        min_cvss: float | None = None,
        min_epss: float | None = None,
    ) -> list[PrioritizedFindingItem]:
        findings = await self._finding_repo.list_all_active()

        items: list[PrioritizedFindingItem] = []
        for f in findings:
            in_kev = self._kev_matcher.is_in_kev(f.vuln_id)

            if kev_only and not in_kev:
                continue
            if min_cvss is not None and (f.cvss_v3_base_score or 0.0) < min_cvss:
                continue
            if min_epss is not None and (f.epss_score or 0.0) < min_epss:
                continue

            score = self._svc.score(f, in_kev)
            items.append(PrioritizedFindingItem(finding=f, score=score))

        items.sort(key=lambda item: item.score.value, reverse=True)
        return items
