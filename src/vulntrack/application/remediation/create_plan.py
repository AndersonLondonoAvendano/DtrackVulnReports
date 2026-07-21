"""T-067 / T-E019: Caso de uso CreatePlan -- un plan siempre pertenece a un
sprint (P5/P1, iter4-design.md): sin sprint no hay dónde materializar sus
tratamientos."""
from __future__ import annotations

from vulntrack.domain.entities.remediation import RemediationPlan
from vulntrack.domain.exceptions import DomainError
from vulntrack.domain.ports.remediation_repository import RemediationRepository
from vulntrack.domain.ports.sprint_repository import SprintRepository


class SprintNotFoundError(DomainError):
    def __init__(self, sprint_id: int) -> None:
        super().__init__(f"El sprint {sprint_id} no existe")
        self.sprint_id = sprint_id


class CreatePlanUseCase:
    def __init__(self, repo: RemediationRepository, sprint_repo: SprintRepository) -> None:
        self._repo = repo
        self._sprint_repo = sprint_repo

    async def execute(
        self,
        project_uuid: str,
        name: str,
        description: str | None = None,
        sprint_id: int | None = None,
    ) -> RemediationPlan:
        if sprint_id is not None:
            sprint = await self._sprint_repo.get_by_id(sprint_id)
            if sprint is None:
                raise SprintNotFoundError(sprint_id)
        return await self._repo.create_plan(project_uuid, name, description, sprint_id)
