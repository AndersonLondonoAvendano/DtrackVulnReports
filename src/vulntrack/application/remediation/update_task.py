"""T-067: Caso de uso UpdateTask — actualiza estado y metadatos de una tarea."""
from __future__ import annotations

from datetime import UTC, date, datetime

from vulntrack.domain.entities.remediation import RemediationTask, TaskStatus
from vulntrack.domain.exceptions import DomainError
from vulntrack.domain.ports.remediation_repository import RemediationRepository

# Transiciones de estado válidas: estado_actual -> {estados_permitidos}
_VALID_TRANSITIONS: dict[TaskStatus, set[TaskStatus]] = {
    TaskStatus.PENDING: {TaskStatus.IN_PROGRESS, TaskStatus.DISCARDED},
    TaskStatus.IN_PROGRESS: {TaskStatus.COMPLETED, TaskStatus.DISCARDED, TaskStatus.PENDING},
    TaskStatus.COMPLETED: {TaskStatus.IN_PROGRESS},
    TaskStatus.DISCARDED: {TaskStatus.PENDING},
}


class InvalidTaskTransitionError(DomainError):
    def __init__(self, from_status: TaskStatus, to_status: TaskStatus) -> None:
        super().__init__(
            f"Transición inválida: {from_status} → {to_status}"
        )


class UpdateTaskUseCase:
    def __init__(self, repo: RemediationRepository) -> None:
        self._repo = repo

    async def execute(
        self,
        task_id: int,
        *,
        status: TaskStatus | None = None,
        assignee: str | None = None,
        notes: str | None = None,
        target_date: date | None = None,
    ) -> RemediationTask:
        tasks = await self._repo.list_tasks_by_plan(0)  # placeholder; repo fetches by id
        # Fetch task via plan listing — repositories expose list_tasks_by_plan;
        # we rely on repo.update_task to handle lookup.
        fields: dict[str, object] = {}

        if status is not None:
            fields["status"] = status
            if status == TaskStatus.COMPLETED:
                fields["completed_at"] = datetime.now(UTC)
            elif status != TaskStatus.COMPLETED:
                fields["completed_at"] = None

        if assignee is not None:
            fields["assignee"] = assignee
        if notes is not None:
            fields["notes"] = notes
        if target_date is not None:
            fields["target_date"] = target_date

        return await self._repo.update_task(task_id, **fields)

    async def execute_with_validation(
        self,
        task: RemediationTask,
        *,
        status: TaskStatus | None = None,
        assignee: str | None = None,
        notes: str | None = None,
        target_date: date | None = None,
    ) -> RemediationTask:
        if status is not None and status != task.status:
            allowed = _VALID_TRANSITIONS.get(task.status, set())
            if status not in allowed:
                raise InvalidTaskTransitionError(task.status, status)

        fields: dict[str, object] = {}
        if status is not None:
            fields["status"] = status
            if status == TaskStatus.COMPLETED:
                fields["completed_at"] = datetime.now(UTC)
            else:
                fields["completed_at"] = None
        if assignee is not None:
            fields["assignee"] = assignee
        if notes is not None:
            fields["notes"] = notes
        if target_date is not None:
            fields["target_date"] = target_date

        return await self._repo.update_task(task.id, **fields)
