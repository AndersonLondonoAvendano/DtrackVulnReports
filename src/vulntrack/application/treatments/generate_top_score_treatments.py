"""T-E024: genera tratamientos automáticamente a partir de las N vulnerabilidades
disponibles con mayor score de prioridad para el proyecto del plan (P3 --
alternativa "genérica" al alta manual una por una)."""
from __future__ import annotations

from vulntrack.application.queries.available_vulnerabilities_query import (
    ListAvailableVulnerabilitiesQuery,
)
from vulntrack.application.treatments.create_treatments import (
    CreateTreatmentsUseCase,
    TreatmentSelection,
)
from vulntrack.domain.entities.vulnerability_treatment import TratamientoVulnerabilidad


class GenerateTreatmentsFromTopScoreUseCase:
    def __init__(
        self,
        available_query: ListAvailableVulnerabilitiesQuery,
        create_treatments_uc: CreateTreatmentsUseCase,
    ) -> None:
        self._available_query = available_query
        self._create_treatments_uc = create_treatments_uc

    async def execute(
        self,
        *,
        project_uuid: str,
        plan_id: int,
        sprint_id: int,
        top_n: int,
    ) -> list[TratamientoVulnerabilidad]:
        # `ListAvailableVulnerabilitiesQuery.execute` ya ordena desc por score.
        items = await self._available_query.execute(project_uuid)
        top_items = items[:top_n]
        selections = [
            TreatmentSelection(finding_id=item.finding.id) for item in top_items
        ]
        return await self._create_treatments_uc.execute(
            project_uuid=project_uuid,
            sprint_id=sprint_id,
            plan_id=plan_id,
            selections=selections,
        )
