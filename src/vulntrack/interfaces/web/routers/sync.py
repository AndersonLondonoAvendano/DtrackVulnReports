"""T-073: Router de sincronización — POST /api/v1/sync/run y GET /api/v1/sync/status."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends

from vulntrack.application.sync.sync_portfolio import SyncPortfolioUseCase
from vulntrack.interfaces.web.dependencies import get_sync_portfolio_use_case
from vulntrack.interfaces.web.schemas.sync import SyncStatusOut, SyncTriggerOut

router = APIRouter(prefix="/api/v1/sync", tags=["sync"])

# Estado en memoria del último sync (suficiente para MVP)
_last_sync_result: dict[str, Any] = {}
_sync_running: bool = False


async def _run_sync(uc: SyncPortfolioUseCase) -> None:
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
