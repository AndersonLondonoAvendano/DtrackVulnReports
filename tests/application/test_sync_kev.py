"""Tests T-062: SyncKevUseCase."""
from __future__ import annotations

from datetime import date
from unittest.mock import AsyncMock

import pytest

from vulntrack.application.sync.sync_kev import SyncKevUseCase
from vulntrack.domain.entities.kev_entry import KevEntry


def _kev_entry(cve_id: str, date_added: date = date(2026, 1, 1)) -> KevEntry:
    return KevEntry(
        cve_id=cve_id,
        vendor_project="Vendor",
        product="Product",
        vulnerability_name=f"Vuln {cve_id}",
        date_added=date_added,
        short_description="desc",
        required_action="patch",
        due_date=None,
        notes=None,
    )


class TestSyncKevUseCase:
    @pytest.mark.asyncio
    async def test_empty_catalog_upserts_zero(self) -> None:
        client = AsyncMock()
        client.fetch.return_value = []
        repo = AsyncMock()

        uc = SyncKevUseCase(client, repo)
        result = await uc.execute()

        assert result.entries_synced == 0
        repo.upsert_batch.assert_called_once_with([])
        repo.update_catalog_meta.assert_called_once()

    @pytest.mark.asyncio
    async def test_catalog_with_entries(self) -> None:
        entries = [_kev_entry(f"CVE-2026-{i:04d}", date(2026, 1, i)) for i in range(1, 6)]
        client = AsyncMock()
        client.fetch.return_value = entries
        repo = AsyncMock()

        uc = SyncKevUseCase(client, repo)
        result = await uc.execute()

        assert result.entries_synced == 5
        assert result.catalog_date == date(2026, 1, 5)
        repo.upsert_batch.assert_called_once_with(entries)

    @pytest.mark.asyncio
    async def test_catalog_date_is_max_date_added(self) -> None:
        entries = [
            _kev_entry("CVE-A", date(2025, 6, 1)),
            _kev_entry("CVE-B", date(2026, 3, 15)),
            _kev_entry("CVE-C", date(2024, 12, 31)),
        ]
        client = AsyncMock()
        client.fetch.return_value = entries
        repo = AsyncMock()

        uc = SyncKevUseCase(client, repo)
        result = await uc.execute()

        assert result.catalog_date == date(2026, 3, 15)
