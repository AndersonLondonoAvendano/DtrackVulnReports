from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vulntrack.domain.entities.project import Project
from vulntrack.infrastructure.persistence.mappers import orm_to_project
from vulntrack.infrastructure.persistence.orm_models import ProjectORM


class SqliteProjectRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert(self, project: Project) -> None:
        now = datetime.now(UTC)
        existing = await self._session.get(ProjectORM, project.uuid)
        if existing is None:
            row = ProjectORM(
                uuid=project.uuid,
                name=project.name,
                version=project.version,
                description=project.description,
                last_bom_import=project.last_bom_import,
                last_synced_at=project.last_synced_at,
                created_at=now,
                updated_at=now,
            )
            self._session.add(row)
        else:
            existing.name = project.name
            existing.version = project.version
            existing.description = project.description
            existing.last_bom_import = project.last_bom_import
            existing.last_synced_at = project.last_synced_at
            existing.updated_at = now

    async def get_by_uuid(self, uuid: str) -> Project | None:
        row = await self._session.get(ProjectORM, uuid)
        return orm_to_project(row) if row is not None else None

    async def list_all(self) -> list[Project]:
        result = await self._session.execute(
            select(ProjectORM).order_by(ProjectORM.name)
        )
        return [orm_to_project(r) for r in result.scalars().all()]

    async def count(self) -> int:
        result = await self._session.execute(select(func.count()).select_from(ProjectORM))
        return result.scalar_one()
