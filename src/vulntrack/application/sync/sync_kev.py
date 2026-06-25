"""T-062: Caso de uso SyncKev — descarga y persiste el catálogo CISA KEV."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Protocol

from vulntrack.domain.entities.kev_entry import KevEntry
from vulntrack.domain.ports.kev_repository import KevRepository

logger = logging.getLogger(__name__)


class KevClientPort(Protocol):
    async def fetch(self) -> list[KevEntry]: ...


@dataclass
class KevSyncResult:
    entries_synced: int = 0
    catalog_date: date | None = None
    fetched_at: datetime | None = None


class SyncKevUseCase:
    def __init__(
        self,
        kev_client: KevClientPort,
        kev_repo: KevRepository,
    ) -> None:
        self._client = kev_client
        self._kev_repo = kev_repo

    async def execute(self) -> KevSyncResult:
        fetched_at = datetime.now(UTC)
        entries = await self._client.fetch()

        await self._kev_repo.upsert_batch(entries)

        catalog_date: date | None = None
        if entries:
            catalog_date = max(e.date_added for e in entries)

        await self._kev_repo.update_catalog_meta(
            total_entries=len(entries),
            catalog_updated_at=catalog_date or date.today(),
            last_fetched_at=fetched_at,
        )

        logger.info(
            "sync_kev_done entries=%d catalog_date=%s", len(entries), catalog_date
        )
        return KevSyncResult(
            entries_synced=len(entries),
            catalog_date=catalog_date,
            fetched_at=fetched_at,
        )
