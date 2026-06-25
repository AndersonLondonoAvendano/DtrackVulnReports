from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from vulntrack.infrastructure.persistence.orm_models import AppSettingsORM

_SINGLETON_ID = 1


@dataclass
class AppSettings:
    id: int
    sync_interval_hours: int
    kev_stale_days: int
    last_sync_at: datetime | None
    last_kev_update_at: datetime | None
    w_cvss_weight: float
    w_epss_weight: float
    w_kev_weight: float
    kev_minimum_score: float
    epss_high_threshold: float
    cvss_high_threshold: float
    updated_at: datetime


def _orm_to_settings(row: AppSettingsORM) -> AppSettings:
    return AppSettings(
        id=row.id,
        sync_interval_hours=row.sync_interval_hours,
        kev_stale_days=row.kev_stale_days,
        last_sync_at=row.last_sync_at,
        last_kev_update_at=row.last_kev_update_at,
        w_cvss_weight=row.w_cvss_weight,
        w_epss_weight=row.w_epss_weight,
        w_kev_weight=row.w_kev_weight,
        kev_minimum_score=row.kev_minimum_score,
        epss_high_threshold=row.epss_high_threshold,
        cvss_high_threshold=row.cvss_high_threshold,
        updated_at=row.updated_at,
    )


class SqliteAppSettingsRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self) -> AppSettings:
        row = await self._session.get(AppSettingsORM, _SINGLETON_ID)
        if row is None:
            now = datetime.now(UTC)
            row = AppSettingsORM(
                id=_SINGLETON_ID,
                sync_interval_hours=6,
                kev_stale_days=7,
                last_sync_at=None,
                last_kev_update_at=None,
                w_cvss_weight=0.30,
                w_epss_weight=0.40,
                w_kev_weight=0.30,
                kev_minimum_score=0.75,
                epss_high_threshold=0.40,
                cvss_high_threshold=7.0,
                updated_at=now,
            )
            self._session.add(row)
            await self._session.flush()
        return _orm_to_settings(row)

    async def update(self, **fields: object) -> AppSettings:
        row = await self._session.get(AppSettingsORM, _SINGLETON_ID)
        if row is None:
            await self.get()
            row = await self._session.get(AppSettingsORM, _SINGLETON_ID)
            assert row is not None

        updatable = {
            "sync_interval_hours", "kev_stale_days", "last_sync_at",
            "last_kev_update_at", "w_cvss_weight", "w_epss_weight",
            "w_kev_weight", "kev_minimum_score", "epss_high_threshold",
            "cvss_high_threshold",
        }
        for key, value in fields.items():
            if key in updatable:
                setattr(row, key, value)
        row.updated_at = datetime.now(UTC)
        await self._session.flush()
        return _orm_to_settings(row)
