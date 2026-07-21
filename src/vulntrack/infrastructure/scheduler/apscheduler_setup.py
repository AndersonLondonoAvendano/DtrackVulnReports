"""T-072: Configuración del scheduler (APScheduler) para jobs periódicos."""
from __future__ import annotations

import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from fastapi import FastAPI

from vulntrack.config import Settings
from vulntrack.infrastructure.persistence.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

_scheduler: AsyncIOScheduler | None = None


def get_scheduler() -> AsyncIOScheduler | None:
    return _scheduler


async def _sync_portfolio_job() -> None:
    from vulntrack.logging_config import reenable_vulntrack_loggers
    reenable_vulntrack_loggers()
    logger.info("scheduler_job_start job=sync_portfolio")
    try:
        from vulntrack.application.sync.sync_portfolio import SyncPortfolioUseCase
        from vulntrack.infrastructure.dt.client import DtHttpClient
        from vulntrack.infrastructure.persistence.repositories.finding_repo import (
            SqliteFindingRepository,
        )
        from vulntrack.infrastructure.persistence.repositories.project_repo import (
            SqliteProjectRepository,
        )
        from vulntrack.infrastructure.persistence.repositories.snapshot_repo import (
            SqliteSnapshotRepository,
        )
        from vulntrack.infrastructure.persistence.repositories.app_settings_repo import (
            SqliteAppSettingsRepository,
        )
        from vulntrack.config import get_settings
        import asyncio

        settings = get_settings()
        async with AsyncSessionLocal() as session:
            uc = SyncPortfolioUseCase(
                dt_client=DtHttpClient(
                    base_url=settings.dt_base_url_str,
                    api_key=settings.dt_api_key,
                    semaphore=asyncio.Semaphore(5),
                ),
                project_repo=SqliteProjectRepository(session),
                finding_repo=SqliteFindingRepository(session),
                snapshot_repo=SqliteSnapshotRepository(session),
                app_settings_repo=SqliteAppSettingsRepository(session),
            )
            result = await uc.execute()
            await session.commit()
            logger.info(
                "scheduler_job_done job=sync_portfolio synced=%d failed=%d duration=%.1fs",
                result.synced_projects,
                result.failed_projects,
                result.duration_seconds,
            )
    except Exception as exc:
        logger.error("scheduler_job_error job=sync_portfolio error=%s", exc)


async def _sync_kev_job() -> None:
    from vulntrack.logging_config import reenable_vulntrack_loggers
    reenable_vulntrack_loggers()
    logger.info("scheduler_job_start job=sync_kev")
    try:
        from vulntrack.application.sync.sync_kev import SyncKevUseCase
        from vulntrack.infrastructure.kev.cisa_kev_client import CisaKevClient
        from vulntrack.infrastructure.persistence.repositories.kev_repo import SqliteKevRepository

        async with AsyncSessionLocal() as session:
            uc = SyncKevUseCase(
                kev_client=CisaKevClient(),
                kev_repo=SqliteKevRepository(session),
            )
            result = await uc.execute()
            logger.info(
                "scheduler_job_done job=sync_kev entries=%d catalog_date=%s",
                result.entries_synced,
                result.catalog_date,
            )
    except Exception as exc:
        logger.error("scheduler_job_error job=sync_kev error=%s", exc)


def setup_scheduler(app: FastAPI, settings: Settings) -> AsyncIOScheduler:
    global _scheduler

    scheduler = AsyncIOScheduler(timezone="UTC")

    scheduler.add_job(
        _sync_portfolio_job,
        trigger=IntervalTrigger(hours=settings.sync_interval_hours),
        id="sync_portfolio",
        coalesce=True,
        max_instances=1,
        replace_existing=True,
    )

    scheduler.add_job(
        _sync_kev_job,
        trigger=CronTrigger(hour=1, minute=0),
        id="sync_kev",
        coalesce=True,
        max_instances=1,
        replace_existing=True,
    )

    scheduler.start()
    _scheduler = scheduler
    logger.info("scheduler_started jobs=%d", len(scheduler.get_jobs()))
    return scheduler
