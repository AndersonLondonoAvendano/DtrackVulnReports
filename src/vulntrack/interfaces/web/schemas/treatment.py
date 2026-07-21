"""T-D036: schemas Pydantic para sprints y tratamientos de vulnerabilidades."""
from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel, Field, model_validator

_REASON_REQUIRED_STATES = {"POSPUESTA", "DESCARTADA"}


class SprintCreateRequest(BaseModel):
    nombre: str
    fecha_inicio: date
    fecha_fin: date
    anio: int | None = None
    trimestre: int | None = None
    origen: str = "MANUAL"
    external_id: str | None = None


class SprintUpdateRequest(BaseModel):
    nombre: str | None = None
    fecha_inicio: date | None = None
    fecha_fin: date | None = None
    external_id: str | None = None


class SprintOut(BaseModel):
    id: int
    nombre: str
    anio: int
    trimestre: int
    fecha_inicio: date
    fecha_fin: date
    estado: str
    origen: str
    external_id: str | None
    created_at: datetime
    updated_at: datetime


class TreatmentSelectionIn(BaseModel):
    finding_id: int
    responsable: str | None = None


class CreateTreatmentsRequest(BaseModel):
    sprint_id: int
    plan_id: int | None = None
    selections: list[TreatmentSelectionIn]


class GenerateTreatmentsRequest(BaseModel):
    sprint_id: int
    top_n: int = Field(default=10, ge=1, le=100)


class RemoveTreatmentResult(BaseModel):
    result: str


class UpdateTreatmentRequest(BaseModel):
    estado: str | None = None
    sprint_id: int | None = None
    responsable: str | None = None
    fecha_objetivo: date | None = None
    notas: str | None = None
    motivo: str | None = None

    @model_validator(mode="after")
    def _validar_motivo_requerido(self) -> "UpdateTreatmentRequest":
        # D2/D3 (iter3-design.md §4.1): POSPUESTA/DESCARTADA exigen motivo.
        # Se valida también aquí (además de en el caso de uso) para devolver
        # 422 con mensaje claro antes de llegar a la capa de aplicación.
        if self.estado in _REASON_REQUIRED_STATES and not self.motivo:
            raise ValueError(f"Se requiere 'motivo' para pasar a estado {self.estado}")
        return self


class TreatmentOut(BaseModel):
    id: int
    project_uuid: str
    vuln_key: str
    cve_id: str | None
    finding_id: int | None
    plan_id: int | None
    sprint_id: int
    responsable: str | None
    estado: str
    priority_band: str
    fecha_creacion: datetime
    fecha_objetivo: date | None
    fecha_cierre: datetime | None
    notas: str | None
    motivo: str | None
    recurrence_flag: bool
    recurrence_count: int
    last_recurrence_at: datetime | None
    created_at: datetime
    updated_at: datetime
    component_name: str | None = None
    component_version: str | None = None
    finalizacion_subtipo: str | None = None
    activo_en_plan: bool = True


class AvailableVulnerabilityOut(BaseModel):
    finding_id: int
    vuln_id: str
    cve_id: str | None
    component_name: str
    component_version: str | None
    severity: str
    priority_score: float
    priority_band: str
    is_kev: bool
    previous_no_cumplida_sprint_id: int | None


class TreatmentSummaryOut(BaseModel):
    """Resumen de tratamiento embebido en la fila de Priorización (T-D037)."""

    treatment_id: int
    sprint_id: int
    sprint_nombre: str
    estado: str
    responsable: str | None
    fecha_objetivo: date | None
