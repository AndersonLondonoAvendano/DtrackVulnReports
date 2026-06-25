from dataclasses import dataclass
from datetime import date, datetime
from typing import Protocol

from vulntrack.domain.entities.kev_entry import KevEntry


@dataclass
class KevCatalogMeta:
    total_entries: int
    catalog_updated_at: datetime
    last_fetched_at: datetime | None


class KevRepository(Protocol):
    async def upsert_batch(self, entries: list[KevEntry]) -> None: ...

    async def get_by_cve_id(self, cve_id: str) -> KevEntry | None: ...

    async def is_cve_in_kev(self, cve_id: str) -> bool: ...

    async def list_all(self) -> list[KevEntry]: ...

    async def get_catalog_meta(self) -> KevCatalogMeta | None: ...

    async def update_catalog_meta(
        self,
        total_entries: int,
        catalog_updated_at: date,
        last_fetched_at: datetime,
    ) -> None: ...
