from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulntrack.domain.entities.remediation import RemediationPlan
from vulntrack.infrastructure.persistence.mappers import orm_to_plan
from vulntrack.infrastructure.persistence.orm_models import RemediationPlanORM


class SqliteRemediationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create_plan(
        self,
        project_uuid: str,
        name: str,
        description: str | None,
        sprint_id: int | None,
    ) -> RemediationPlan:
        now = datetime.now(UTC)
        row = RemediationPlanORM(
            project_uuid=project_uuid,
            name=name,
            description=description,
            sprint_id=sprint_id,
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
