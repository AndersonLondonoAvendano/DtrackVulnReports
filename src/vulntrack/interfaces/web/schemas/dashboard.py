from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class TaskSummaryOut(BaseModel):
    total: int
    pending: int
    in_progress: int
    completed: int


class DashboardOut(BaseModel):
    total_vigentes: int
    vigentes_por_severidad: dict[str, int]
    proyectos_en_cero: int
    proyectos_con_criticas: int
    last_sync_at: datetime | None
    kev_hits_count: int
    total_proyectos: int
    tasks_summary: TaskSummaryOut
