"""T-D045: schemas Pydantic para métricas de avance de remediación por Q."""
from __future__ import annotations

from pydantic import BaseModel


class QuarterlyMetricsCoreOut(BaseModel):
    entraron: int
    resueltas: int
    pospuestas: int
    no_cumplidas: int
    en_curso: int
    descartadas: int
    resueltas_sin_seguimiento: int
    pct_cumplimiento: float | None


class SprintTrendOut(BaseModel):
    sprint_id: int
    sprint_nombre: str
    core: QuarterlyMetricsCoreOut


class QuarterlyMetricsOut(BaseModel):
    anio: int
    trimestre: int
    core: QuarterlyMetricsCoreOut
    por_severidad: dict[str, QuarterlyMetricsCoreOut]
    por_proyecto: dict[str, QuarterlyMetricsCoreOut]
    tendencia_por_sprint: list[SprintTrendOut]
