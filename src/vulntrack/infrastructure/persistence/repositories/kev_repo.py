from __future__ import annotations

from datetime import UTC, date, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vulntrack.domain.entities.kev_entry import KevEntry
from vulntrack.domain.ports.kev_repository import KevCatalogMeta
from vulntrack.infrastructure.persistence.mappers import orm_to_kev
from vulntrack.infrastructure.persistence.orm_models import KevEntryORM


class SqliteKevRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert_batch(self, entries: list[KevEntry]) -> None:
        now = datetime.now(UTC)
        for entry in entries:
            existing = await self._session.get(KevEntryORM, entry.cve_id)
            if existing is None:
                row = KevEntryORM(
                    cve_id=entry.cve_id,
                    vendor_project=entry.vendor_project,
                    product=entry.product,
                    vulnerability_name=entry.vulnerability_name,
                    date_added=entry.date_added,
                    short_description=entry.short_description,
                    required_action=entry.required_action,
                    due_date=entry.due_date,
                    notes=entry.notes,
                    catalog_updated_at=now,
                )
                self._session.add(row)
            else:
                existing.vendor_project = entry.vendor_project
                existing.product = entry.product
                existing.vulnerability_name = entry.vulnerability_name
                existing.date_added = entry.date_added
                existing.short_description = entry.short_description
                existing.required_action = entry.required_action
                existing.due_date = entry.due_date
                existing.notes = entry.notes
                existing.catalog_updated_at = now

    async def get_by_cve_id(self, cve_id: str) -> KevEntry | None:
        row = await self._session.get(KevEntryORM, cve_id)
        return orm_to_kev(row) if row is not None else None

    async def is_cve_in_kev(self, cve_id: str) -> bool:
        result = await self._session.execute(
            select(func.count(1)).select_from(KevEntryORM).where(KevEntryORM.cve_id == cve_id)
        )
        return result.scalar_one() > 0

    async def list_all(self) -> list[KevEntry]:
        result = await self._session.execute(select(KevEntryORM))
        return [orm_to_kev(r) for r in result.scalars().all()]

    async def get_catalog_meta(self) -> KevCatalogMeta | None:
        count_result = await self._session.execute(
            select(func.count()).select_from(KevEntryORM)
        )
        total = count_result.scalar_one()
        if total == 0:
            return None

        last_result = await self._session.execute(
            select(func.max(KevEntryORM.catalog_updated_at))
        )
        last_updated = last_result.scalar_one()
        if last_updated is None:
            return None

        return KevCatalogMeta(
            total_entries=total,
            catalog_updated_at=last_updated,
            last_fetched_at=last_updated,
        )

    async def update_catalog_meta(
        self,
        total_entries: int,
        catalog_updated_at: date,
        last_fetched_at: datetime,
    ) -> None:
        pass
