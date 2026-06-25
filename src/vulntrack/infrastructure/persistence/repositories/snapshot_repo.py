from __future__ import annotations

from datetime import UTC, date, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vulntrack.domain.entities.metric_snapshot import MetricSnapshot
from vulntrack.infrastructure.persistence.mappers import orm_to_snapshot
from vulntrack.infrastructure.persistence.orm_models import MetricSnapshotORM


class SqliteSnapshotRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert(self, snapshot: MetricSnapshot) -> None:
        result = await self._session.execute(
            select(MetricSnapshotORM).where(
                MetricSnapshotORM.project_uuid == snapshot.project_uuid,
                MetricSnapshotORM.snapshot_date == snapshot.snapshot_date,
            )
        )
        existing = result.scalar_one_or_none()
        if existing is None:
            row = MetricSnapshotORM(
                project_uuid=snapshot.project_uuid,
                snapshot_date=snapshot.snapshot_date,
                critical=snapshot.critical,
                high=snapshot.high,
                medium=snapshot.medium,
                low=snapshot.low,
                unassigned=snapshot.unassigned,
                total=snapshot.total,
                risk_score=snapshot.risk_score,
                source=snapshot.source.value,
                created_at=datetime.now(UTC),
            )
            self._session.add(row)
        else:
            existing.critical = snapshot.critical
            existing.high = snapshot.high
            existing.medium = snapshot.medium
            existing.low = snapshot.low
            existing.unassigned = snapshot.unassigned
            existing.total = snapshot.total
            existing.risk_score = snapshot.risk_score
            existing.source = snapshot.source.value

    async def get_closest_before(
        self, project_uuid: str, ref_date: date
    ) -> MetricSnapshot | None:
        result = await self._session.execute(
            select(MetricSnapshotORM)
            .where(
                MetricSnapshotORM.project_uuid == project_uuid,
                MetricSnapshotORM.snapshot_date <= ref_date,
            )
            .order_by(MetricSnapshotORM.snapshot_date.desc())
            .limit(1)
        )
        row = result.scalar_one_or_none()
        return orm_to_snapshot(row) if row is not None else None

    async def get_closest_after(
        self, project_uuid: str, ref_date: date
    ) -> MetricSnapshot | None:
        result = await self._session.execute(
            select(MetricSnapshotORM)
            .where(
                MetricSnapshotORM.project_uuid == project_uuid,
                MetricSnapshotORM.snapshot_date >= ref_date,
            )
            .order_by(MetricSnapshotORM.snapshot_date.asc())
            .limit(1)
        )
        row = result.scalar_one_or_none()
        return orm_to_snapshot(row) if row is not None else None

    async def list_by_project_in_range(
        self, project_uuid: str, date_from: date, date_to: date
    ) -> list[MetricSnapshot]:
        result = await self._session.execute(
            select(MetricSnapshotORM)
            .where(
                MetricSnapshotORM.project_uuid == project_uuid,
                MetricSnapshotORM.snapshot_date >= date_from,
                MetricSnapshotORM.snapshot_date <= date_to,
            )
            .order_by(MetricSnapshotORM.snapshot_date.asc())
        )
        return [orm_to_snapshot(r) for r in result.scalars().all()]

    async def count_by_source(self, source: str) -> int:
        result = await self._session.execute(
            select(func.count()).select_from(MetricSnapshotORM).where(
                MetricSnapshotORM.source == source
            )
        )
        return result.scalar_one()
