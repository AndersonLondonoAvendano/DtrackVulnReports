"""T-D045: Router de métricas de avance de remediación por Q."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from vulntrack.application.queries.quarterly_metrics_query import (
    QuarterlyMetrics,
    QuarterlyMetricsCore,
    QuarterlyMetricsQuery,
)
from vulntrack.interfaces.web.dependencies import get_quarterly_metrics_query
from vulntrack.interfaces.web.schemas.metrics import (
    QuarterlyMetricsCoreOut,
    QuarterlyMetricsOut,
    SprintTrendOut,
)

router = APIRouter(prefix="/api/v1/metrics", tags=["metricas"])


def _core_out(core: QuarterlyMetricsCore) -> QuarterlyMetricsCoreOut:
    return QuarterlyMetricsCoreOut(
        entraron=core.entraron,
        resueltas=core.resueltas,
        pospuestas=core.pospuestas,
        no_cumplidas=core.no_cumplidas,
        en_curso=core.en_curso,
        descartadas=core.descartadas,
        resueltas_sin_seguimiento=core.resueltas_sin_seguimiento,
        pct_cumplimiento=core.pct_cumplimiento,
    )


def _metrics_out(result: QuarterlyMetrics) -> QuarterlyMetricsOut:
    return QuarterlyMetricsOut(
        anio=result.anio,
        trimestre=result.trimestre,
        core=_core_out(result.core),
        por_severidad={k: _core_out(v) for k, v in result.por_severidad.items()},
        por_proyecto={k: _core_out(v) for k, v in result.por_proyecto.items()},
        tendencia_por_sprint=[
            SprintTrendOut(
                sprint_id=t.sprint_id, sprint_nombre=t.sprint_nombre, core=_core_out(t.core)
            )
            for t in result.tendencia_por_sprint
        ],
    )


@router.get("/quarterly", response_model=QuarterlyMetricsOut)
async def get_quarterly_metrics(
    anio: int = Query(...),
    trimestre: int = Query(..., ge=1, le=4),
    project_uuid: str | None = Query(default=None),
    query: QuarterlyMetricsQuery = Depends(get_quarterly_metrics_query),  # noqa: B008
) -> QuarterlyMetricsOut:
    result = await query.execute(anio, trimestre, project_uuid=project_uuid)
    return _metrics_out(result)
