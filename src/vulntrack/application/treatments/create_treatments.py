"""T-D021: caso de uso CreateTreatments -- crea tratamientos en bloque a partir
de vulnerabilidades seleccionadas manualmente.

Anti-duplicación (D2) en la capa de aplicación: el índice único parcial de BD
(T-D001) es la garantía real; aquí sólo se traduce el `IntegrityError` que
produce en un `DomainError` 409 legible para la API, en vez de un 500 crudo.
Esto cubre la condición de carrera entre dos usuarios tomando la misma
vulnerabilidad al mismo tiempo (riesgo identificado en iter3-plan.md §12).
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.exc import IntegrityError

from vulntrack.domain.entities.vulnerability_treatment import (
    TratamientoVulnerabilidad,
    TreatmentStatus,
)
from vulntrack.domain.exceptions import DomainError
from vulntrack.domain.ports.finding_repository import FindingRepository
from vulntrack.domain.ports.treatment_repository import TreatmentRepository
from vulntrack.domain.services.kev_matcher import KevMatcher
from vulntrack.domain.services.prioritization import PrioritizationService, PriorityWeights
from vulntrack.domain.services.vuln_identity import identity_key


class TreatmentAlreadyTakenError(DomainError):
    def __init__(self, vuln_key: str) -> None:
        super().__init__(f"La vulnerabilidad {vuln_key} ya fue tomada por otro plan")
        self.vuln_key = vuln_key


class FindingNotInProjectError(DomainError):
    def __init__(self, finding_id: int, project_uuid: str) -> None:
        super().__init__(f"El finding {finding_id} no pertenece al proyecto {project_uuid}")
        self.finding_id = finding_id
        self.project_uuid = project_uuid


@dataclass
class TreatmentSelection:
    finding_id: int
    responsable: str | None = None


class CreateTreatmentsUseCase:
    def __init__(
        self,
        treatment_repo: TreatmentRepository,
        finding_repo: FindingRepository,
        kev_matcher: KevMatcher,
        weights: PriorityWeights | None = None,
    ) -> None:
        self._treatment_repo = treatment_repo
        self._finding_repo = finding_repo
        self._kev_matcher = kev_matcher
        self._svc = PrioritizationService(weights)

    async def execute(
        self,
        *,
        project_uuid: str,
        sprint_id: int,
        plan_id: int | None,
        selections: list[TreatmentSelection],
    ) -> list[TratamientoVulnerabilidad]:
        findings = await self._finding_repo.list_by_project(project_uuid)
        findings_by_id = {f.id: f for f in findings}

        created: list[TratamientoVulnerabilidad] = []
        for selection in selections:
            finding = findings_by_id.get(selection.finding_id)
            if finding is None:
                raise FindingNotInProjectError(selection.finding_id, project_uuid)

            _project_uuid, vuln_key, _component, _version = identity_key(
                project_uuid,
                finding.cve_id,
                finding.vuln_id,
                finding.component_name,
                finding.component_version,
            )
            score = self._svc.score(
                finding, self._kev_matcher.is_in_kev(finding.cve_id, finding.vuln_id)
            )

            try:
                treatment = await self._treatment_repo.create(
                    project_uuid=project_uuid,
                    vuln_key=finding.cve_id or finding.vuln_id,
                    cve_id=finding.cve_id,
                    finding_id=finding.id,
                    plan_id=plan_id,
                    sprint_id=sprint_id,
                    responsable=selection.responsable,
                    priority_band=score.band,
                    component_name=finding.component_name,
                    component_version=finding.component_version,
                )
            except IntegrityError as exc:
                raise TreatmentAlreadyTakenError(vuln_key) from exc

            await self._treatment_repo.append_history(
                treatment.id,
                from_status=None,
                to_status=TreatmentStatus.PENDIENTE,
                sprint_id=sprint_id,
                note=None,
            )
            created.append(treatment)

        return created
