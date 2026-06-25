from typing import Any, Protocol

from vulntrack.domain.entities.remediation import RemediationPlan, RemediationTask


class RemediationRepository(Protocol):
    async def create_plan(
        self, project_uuid: str, name: str, description: str | None
    ) -> RemediationPlan: ...

    async def get_plan(self, plan_id: int) -> RemediationPlan | None: ...

    async def list_plans_by_project(
        self, project_uuid: str
    ) -> list[RemediationPlan]: ...

    async def create_task(
        self, plan_id: int, **fields: Any
    ) -> RemediationTask: ...

    async def update_task(
        self, task_id: int, **fields: Any
    ) -> RemediationTask: ...

    async def list_tasks_by_plan(self, plan_id: int) -> list[RemediationTask]: ...
