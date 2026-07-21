"""T-064: Query de hallazgos priorizados del portafolio completo."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from vulntrack.application.queries._project_lookup import build_project_name_map
from vulntrack.application.queries._sprint_lookup import build_sprint_name_map
from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.vulnerability_treatment import TratamientoVulnerabilidad
from vulntrack.domain.ports.finding_repository import FindingRepository
from vulntrack.domain.ports.project_repository import ProjectRepository
from vulntrack.domain.ports.sprint_repository import SprintRepository
from vulntrack.domain.ports.treatment_repository import TreatmentRepository
from vulntrack.domain.services.kev_matcher import KevMatcher
from vulntrack.domain.services.prioritization import PrioritizationService, PriorityWeights
from vulntrack.domain.value_objects.priority_score import PriorityScore


@dataclass
class TreatmentSummary:
    """T-D037: resumen de tratamiento embebido en cada fila de Priorización."""

    treatment_id: int
    sprint_id: int
    sprint_nombre: str
    estado: str
    responsable: str | None
    fecha_objetivo: date | None


@dataclass
class PrioritizedFindingItem:
    finding: Finding
    score: PriorityScore
    project_name: str
    treatment: TreatmentSummary | None = None


class PrioritizedFindingsQuery:
    def __init__(
        self,
        finding_repo: FindingRepository,
        kev_matcher: KevMatcher,
        project_repo: ProjectRepository,
        treatment_repo: TreatmentRepository | None = None,
        sprint_repo: SprintRepository | None = None,
        weights: PriorityWeights | None = None,
    ) -> None:
        self._finding_repo = finding_repo
        self._kev_matcher = kev_matcher
        self._project_repo = project_repo
        self._treatment_repo = treatment_repo
        self._sprint_repo = sprint_repo
        self._svc = PrioritizationService(weights)

    async def execute(
        self,
        *,
        kev_only: bool = False,
        min_cvss: float | None = None,
        min_epss: float | None = None,
        sprint_id: int | None = None,
        treatment_status: str | None = None,
    ) -> list[PrioritizedFindingItem]:
        findings = await self._finding_repo.list_all_active(
            min_cvss=min_cvss,
            min_epss=min_epss,
        )
        # F1: una sola consulta a `projects` para todo el listado (sin N+1).
        project_names = await build_project_name_map(self._project_repo)

        treatment_by_key: dict[tuple[str, str], TratamientoVulnerabilidad] = {}
        sprint_names: dict[int, str] = {}
        if self._treatment_repo is not None:
            treatments = await self._treatment_repo.list_all()
            treatment_by_key = {(t.project_uuid, t.vuln_key): t for t in treatments}
            if self._sprint_repo is not None:
                sprint_names = await build_sprint_name_map(self._sprint_repo)

        items: list[PrioritizedFindingItem] = []
        for f in findings:
            in_kev = self._kev_matcher.is_in_kev(f.cve_id, f.vuln_id)

            if kev_only and not in_kev:
                continue

            vuln_key = f.cve_id or f.vuln_id
            treatment = treatment_by_key.get((f.project_uuid, vuln_key))

            if sprint_id is not None and (treatment is None or treatment.sprint_id != sprint_id):
                continue
            if treatment_status is not None and (
                treatment is None or treatment.estado.value != treatment_status
            ):
                continue

            score = self._svc.score(f, in_kev)
            project_name = project_names.get(f.project_uuid, f.project_uuid)

            treatment_summary = None
            if treatment is not None:
                treatment_summary = TreatmentSummary(
                    treatment_id=treatment.id,
                    sprint_id=treatment.sprint_id,
                    sprint_nombre=sprint_names.get(
                        treatment.sprint_id, str(treatment.sprint_id)
                    ),
                    estado=treatment.estado.value,
                    responsable=treatment.responsable,
                    fecha_objetivo=treatment.fecha_objetivo,
                )

            items.append(
                PrioritizedFindingItem(
                    finding=f,
                    score=score,
                    project_name=project_name,
                    treatment=treatment_summary,
                )
            )

        items.sort(key=lambda item: item.score.value, reverse=True)
        return items
