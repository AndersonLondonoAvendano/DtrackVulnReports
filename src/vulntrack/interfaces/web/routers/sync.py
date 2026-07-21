"""T-073: Router de sincronización — POST /api/v1/sync/run y GET /api/v1/sync/status."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from fastapi.responses import HTMLResponse

from vulntrack.application.sync.sync_portfolio import SyncPortfolioUseCase
from vulntrack.interfaces.web._shared import templates
from vulntrack.interfaces.web.dependencies import get_sync_portfolio_use_case
from vulntrack.interfaces.web.schemas.sync import SyncStatusOut, SyncTriggerOut

router = APIRouter(prefix="/api/v1/sync", tags=["sync"])
html_router = APIRouter(tags=["sync-html"])

# Estado en memoria del último sync (suficiente para MVP)
_last_sync_result: dict[str, Any] = {}
_sync_running: bool = False


def is_sync_running() -> bool:
    return _sync_running


async def _run_sync(uc: SyncPortfolioUseCase) -> None:
    from vulntrack.logging_config import reenable_vulntrack_loggers
    reenable_vulntrack_loggers()
    global _last_sync_result, _sync_running
    _sync_running = True
    try:
        result = await uc.execute()
        _last_sync_result = {
            "synced_projects": result.synced_projects,
            "failed_projects": result.failed_projects,
            "new_snapshots": result.new_snapshots,
            "duration_seconds": result.duration_seconds,
            "errors": result.errors,
            "status": "idle",
            "last_run_at": datetime.now(UTC).isoformat(),
        }
        # Actualizar last_sync_at con sesión propia: la sesión de la request puede estar
        # en estado inconsistente tras las operaciones concurrentes del sync.
        await _update_last_sync_at(datetime.now(UTC))
    except Exception as exc:
        _last_sync_result = {
            "synced_projects": 0,
            "failed_projects": 0,
            "new_snapshots": 0,
            "duration_seconds": 0.0,
            "errors": [str(exc)],
            "status": "error",
            "last_run_at": datetime.now(UTC).isoformat(),
        }
    finally:
        _sync_running = False


async def _update_last_sync_at(ts: datetime) -> None:
    import logging
    from vulntrack.infrastructure.persistence.database import AsyncSessionLocal
    from vulntrack.infrastructure.persistence.repositories.app_settings_repo import (
        SqliteAppSettingsRepository,
    )

    _logger = logging.getLogger(__name__)
    try:
        async with AsyncSessionLocal() as session:
            repo = SqliteAppSettingsRepository(session)
            await repo.get()
            await repo.update(last_sync_at=ts)
            await session.commit()
    except Exception as exc:
        _logger.warning("sync_last_sync_at_update_failed error=%s", exc)


@router.post("/run", response_model=SyncTriggerOut, status_code=202)
async def trigger_sync(
    background_tasks: BackgroundTasks,
    uc: SyncPortfolioUseCase = Depends(get_sync_portfolio_use_case),  # noqa: B008
) -> SyncTriggerOut:
    if _sync_running:
        return SyncTriggerOut(status="running", message="Sincronización ya en curso")
    background_tasks.add_task(_run_sync, uc)
    return SyncTriggerOut(status="started", message="Sincronización iniciada en segundo plano")


@router.get("/status", response_model=SyncStatusOut)
async def sync_status() -> SyncStatusOut:
    if _sync_running:
        return SyncStatusOut(
            synced_projects=0, failed_projects=0, new_snapshots=0,
            duration_seconds=0.0, errors=[], status="running",
        )
    if not _last_sync_result:
        return SyncStatusOut(
            synced_projects=0, failed_projects=0, new_snapshots=0,
            duration_seconds=0.0, errors=[], status="idle",
        )
    return SyncStatusOut(**_last_sync_result)


# ── HTML routes ───────────────────────────────────────────────────────────────


@html_router.get("/partials/sync-status", response_class=HTMLResponse, include_in_schema=False)
async def sync_status_fragment(request: Request) -> HTMLResponse:
    """Fragmento HTML del indicador de sync para el polling HTMX del dashboard."""
    from vulntrack.infrastructure.persistence.database import AsyncSessionLocal
    from vulntrack.infrastructure.persistence.repositories.app_settings_repo import (
        SqliteAppSettingsRepository,
    )

    async with AsyncSessionLocal() as session:
        repo = SqliteAppSettingsRepository(session)
        cfg = await repo.get()

    return templates.TemplateResponse(
        request,
        "partials/sync_status.html",
        {"sync_running": _sync_running, "last_sync_at": cfg.last_sync_at},
    )
