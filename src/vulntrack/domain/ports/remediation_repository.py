from typing import Protocol

from vulntrack.domain.entities.remediation import RemediationPlan


class RemediationRepository(Protocol):
    async def create_plan(
        self, project_uuid: str, name: str, description: str | None, sprint_id: int | None
    ) -> RemediationPlan: ...

    async def get_plan(self, plan_id: int) -> RemediationPlan | None: ...

    async def list_plans_by_project(
        self, project_uuid: str
    ) -> list[RemediationPlan]: ...
