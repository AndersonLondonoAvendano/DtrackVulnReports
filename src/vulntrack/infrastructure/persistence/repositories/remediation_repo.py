from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulntrack.domain.entities.remediation import RemediationPlan, RemediationTask, TaskStatus
from vulntrack.domain.value_objects.priority_score import PriorityBand
from vulntrack.infrastructure.persistence.mappers import orm_to_plan, orm_to_task
from vulntrack.infrastructure.persistence.orm_models import RemediationPlanORM, RemediationTaskORM


class SqliteRemediationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create_plan(
        self, project_uuid: str, name: str, description: str | None
    ) -> RemediationPlan:
        now = datetime.now(UTC)
        row = RemediationPlanORM(
            project_uuid=project_uuid,
            name=name,
            description=description,
            created_at=now,
            updated_at=now,
        )
        self._session.add(row)
        await self._session.flush()
        return orm_to_plan(row)

    async def get_plan(self, plan_id: int) -> RemediationPlan | None:
        row = await self._session.get(RemediationPlanORM, plan_id)
        return orm_to_plan(row) if row is not None else None

    async def list_plans_by_project(self, project_uuid: str) -> list[RemediationPlan]:
        result = await self._session.execute(
            select(RemediationPlanORM)
            .where(RemediationPlanORM.project_uuid == project_uuid)
            .order_by(RemediationPlanORM.created_at.desc())
        )
        return [orm_to_plan(r) for r in result.scalars().all()]

    async def create_task(self, plan_id: int, **fields: Any) -> RemediationTask:
        now = datetime.now(UTC)
        row = RemediationTaskORM(
            plan_id=plan_id,
            finding_id=fields.get("finding_id"),
            title=fields["title"],
            description=fields.get("description"),
            assignee=fields.get("assignee"),
            status=fields.get("status", TaskStatus.PENDING).value
            if isinstance(fields.get("status"), TaskStatus)
            else fields.get("status", "PENDING"),
            priority_band=fields["priority_band"].value
            if isinstance(fields.get("priority_band"), PriorityBand)
            else fields.get("priority_band", "LOW"),
            recommended_action=fields.get("recommended_action"),
            target_date=fields.get("target_date"),
            completed_at=fields.get("completed_at"),
            notes=fields.get("notes"),
            created_at=now,
            updated_at=now,
        )
        self._session.add(row)
        await self._session.flush()
        return orm_to_task(row)

    async def update_task(self, task_id: int, **fields: Any) -> RemediationTask:
        row = await self._session.get(RemediationTaskORM, task_id)
        if row is None:
            raise ValueError(f"RemediationTask {task_id} not found")

        updatable = {
            "title", "description", "assignee", "status",
            "recommended_action", "target_date", "completed_at", "notes",
        }
        now = datetime.now(UTC)
        for key, value in fields.items():
            if key in updatable:
                if key == "status" and isinstance(value, TaskStatus):
                    row.status = value.value
                elif key == "priority_band" and isinstance(value, PriorityBand):
                    row.priority_band = value.value
                else:
                    setattr(row, key, value)
        row.updated_at = now
        await self._session.flush()
        return orm_to_task(row)

    async def list_tasks_by_plan(self, plan_id: int) -> list[RemediationTask]:
        result = await self._session.execute(
            select(RemediationTaskORM)
            .where(RemediationTaskORM.plan_id == plan_id)
            .order_by(RemediationTaskORM.created_at.asc())
        )
        return [orm_to_task(r) for r in result.scalars().all()]
