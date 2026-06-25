from __future__ import annotations

from pydantic import BaseModel


class SyncStatusOut(BaseModel):
    synced_projects: int
    failed_projects: int
    new_snapshots: int
    duration_seconds: float
    errors: list[str]
    status: str  # "running" | "idle" | "error"


class SyncTriggerOut(BaseModel):
    status: str
    message: str
