from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulntrack.domain.entities.sprint import Sprint
from vulntrack.infrastructure.persistence.mappers import orm_to_sprint
from vulntrack.infrastructure.persistence.orm_models import SprintORM


class SqliteSprintRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        nombre: str,
        anio: int,
        trimestre: int,
        fecha_inicio: date,
        fecha_fin: date,
        origen: str = "MANUAL",
        external_id: str | None = None,
    ) -> Sprint:
        now = datetime.now(UTC)
        row = SprintORM(
            nombre=nombre,
            anio=anio,
            trimestre=trimestre,
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
            estado="PLANEADO",
            origen=origen,
            external_id=external_id,
            created_at=now,
            updated_at=now,
        )
        self._session.add(row)
        await self._session.flush()
        return orm_to_sprint(row)

    async def get_by_id(self, sprint_id: int) -> Sprint | None:
        row = await self._session.get(SprintORM, sprint_id)
        return orm_to_sprint(row) if row is not None else None

    async def list_all(
        self,
        *,
        anio: int | None = None,
        trimestre: int | None = None,
        estado: str | None = None,
    ) -> list[Sprint]:
        stmt = select(SprintORM)
        if anio is not None:
            stmt = stmt.where(SprintORM.anio == anio)
        if trimestre is not None:
            stmt = stmt.where(SprintORM.trimestre == trimestre)
        if estado is not None:
            stmt = stmt.where(SprintORM.estado == estado)
        stmt = stmt.order_by(SprintORM.fecha_inicio.desc())
        result = await self._session.execute(stmt)
        return [orm_to_sprint(r) for r in result.scalars().all()]

    async def close(self, sprint_id: int) -> Sprint:
        row = await self._session.get(SprintORM, sprint_id)
        if row is None:
            raise ValueError(f"Sprint {sprint_id} not found")
        row.estado = "CERRADO"
        row.updated_at = datetime.now(UTC)
        await self._session.flush()
        return orm_to_sprint(row)

    async def update(self, sprint_id: int, **fields: Any) -> Sprint:
        row = await self._session.get(SprintORM, sprint_id)
        if row is None:
            raise ValueError(f"Sprint {sprint_id} not found")

        updatable = {"nombre", "fecha_inicio", "fecha_fin", "external_id"}
        for key, value in fields.items():
            if key in updatable:
                setattr(row, key, value)
        row.updated_at = datetime.now(UTC)
        await self._session.flush()
        return orm_to_sprint(row)
