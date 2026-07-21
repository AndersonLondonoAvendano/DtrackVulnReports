"""T-D020: vulnerabilidades disponibles (sin tratamiento activo) de un proyecto."""
from __future__ import annotations

from dataclasses import dataclass

from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.vulnerability_treatment import TreatmentStatus
from vulntrack.domain.ports.treatment_repository import TreatmentRepository
from vulntrack.domain.services.kev_matcher import KevMatcher
from vulntrack.domain.services.prioritization import PrioritizationService, PriorityWeights
from vulntrack.domain.value_objects.priority_score import PriorityScore


@dataclass
class AvailableVulnerabilityItem:
    finding: Finding
    score: PriorityScore
    # Badge: si esta vulnerabilidad ya se intentó en un sprint anterior y
    # cerró como NO_CUMPLIDA, se muestra distinguible en vez de como "nueva".
    previous_no_cumplida_sprint_id: int | None = None


class ListAvailableVulnerabilitiesQuery:
    def __init__(
        self,
        treatment_repo: TreatmentRepository,
        kev_matcher: KevMatcher,
        weights: PriorityWeights | None = None,
    ) -> None:
        self._treatment_repo = treatment_repo
        self._kev_matcher = kev_matcher
        self._svc = PrioritizationService(weights)

    async def execute(self, project_uuid: str) -> list[AvailableVulnerabilityItem]:
        findings = await self._treatment_repo.list_available_for_project(project_uuid)
        no_cumplida = await self._treatment_repo.list_by_project(
            project_uuid, estado=TreatmentStatus.NO_CUMPLIDA
        )
        no_cumplida_sprint_by_key = {t.vuln_key: t.sprint_id for t in no_cumplida}

        items = [
            AvailableVulnerabilityItem(
                finding=f,
                score=self._svc.score(f, self._kev_matcher.is_in_kev(f.cve_id, f.vuln_id)),
                previous_no_cumplida_sprint_id=no_cumplida_sprint_by_key.get(
                    f.cve_id or f.vuln_id
                ),
            )
            for f in findings
        ]
        items.sort(key=lambda item: item.score.value, reverse=True)
        return items
