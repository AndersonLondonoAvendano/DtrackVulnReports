"""T-073/T-D046: Router de dashboard — GET /api/v1/dashboard y GET /."""
from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse

from vulntrack.application.queries.dashboard_query import DashboardQuery
from vulntrack.application.queries.quarterly_metrics_query import QuarterlyMetricsQuery
from vulntrack.domain.services.quarter import quarter_of
from vulntrack.domain.value_objects.severity import Severity
from vulntrack.interfaces.web.dependencies import (
    get_dashboard_query,
    get_quarterly_metrics_query,
    get_sprint_repo,
)
from vulntrack.interfaces.web.routers.sync import is_sync_running
from vulntrack.interfaces.web.schemas.dashboard import DashboardOut, TaskSummaryOut

router = APIRouter(tags=["dashboard"])

from vulntrack.interfaces.web._shared import templates as _templates  # noqa: E402


@router.get("/api/v1/dashboard", response_model=DashboardOut)
async def get_dashboard(
    query: DashboardQuery = Depends(get_dashboard_query),  # noqa: B008
) -> DashboardOut:
    data = await query.execute()
    return DashboardOut(
        total_vigentes=data.total_vigentes,
        vigentes_por_severidad={
            sev.value: count for sev, count in data.vigentes_por_severidad.items()
        },
        proyectos_en_cero=data.proyectos_en_cero,
        proyectos_con_criticas=data.proyectos_con_criticas,
        last_sync_at=data.last_sync_at,
        kev_hits_count=data.kev_hits_count,
        total_proyectos=data.total_proyectos,
        tasks_summary=TaskSummaryOut(
            total=data.tasks_summary.total,
            pending=data.tasks_summary.pending,
            in_progress=data.tasks_summary.in_progress,
            completed=data.tasks_summary.completed,
        ),
    )


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard_html(
    request: Request,
    anio: int | None = Query(default=None),
    trimestre: int | None = Query(default=None),
    query: DashboardQuery = Depends(get_dashboard_query),  # noqa: B008
    metrics_query: QuarterlyMetricsQuery = Depends(get_quarterly_metrics_query),  # noqa: B008
    sprint_repo: Any = Depends(get_sprint_repo),  # noqa: B008
) -> Any:
    try:
        data = await query.execute()
    except Exception:
        data = None

    if anio is None or trimestre is None:
        anio, trimestre = quarter_of(date.today())

    sprints = await sprint_repo.list_all()
    try:
        metrics = await metrics_query.execute(anio, trimestre)
    except Exception:
        metrics = None

    anios = sorted({s.anio for s in sprints} | {anio})

    context: dict[str, Any] = {
        "titulo": "Dashboard — VulnTrack",
        "data": data,
        "sync_running": is_sync_running(),
        "last_sync_at": data.last_sync_at if data else None,
        "sev_labels": {
            Severity.CRITICAL: "Crítica",
            Severity.HIGH: "Alta",
            Severity.MEDIUM: "Media",
            Severity.LOW: "Baja",
            Severity.UNASSIGNED: "Sin asignar",
        },
        "metrics": metrics,
        "anios": anios,
        "selected_anio": anio,
        "selected_trimestre": trimestre,
    }
    template_name = (
        "partials/quarterly_metrics_section.html"
        if request.headers.get("hx-request") == "true"
        else "dashboard.html"
    )
    return _templates.TemplateResponse(request, template_name, context)
