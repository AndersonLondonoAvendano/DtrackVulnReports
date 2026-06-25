"""T-067: Caso de uso CreatePlan."""
from __future__ import annotations

from vulntrack.domain.entities.remediation import RemediationPlan
from vulntrack.domain.ports.remediation_repository import RemediationRepository


class CreatePlanUseCase:
    def __init__(self, repo: RemediationRepository) -> None:
        self._repo = repo

    async def execute(
        self, project_uuid: str, name: str, description: str | None = None
    ) -> RemediationPlan:
        return await self._repo.create_plan(project_uuid, name, description)
