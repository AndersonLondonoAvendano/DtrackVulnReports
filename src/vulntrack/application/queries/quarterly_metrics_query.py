"""T-D044: métricas de avance de remediación por trimestre (Q) — iter3-design.md §4.6.

Usa `treatment_status_history` (no sólo el estado actual) para que las
métricas sean reproducibles a posteriori aunque un tratamiento se haya
movido de sprint/estado varias veces.

Ajuste respecto al diseño (§4.6, "Entraron"): el texto original define
"Entraron" como la *primera* transición fuera de PENDIENTE, pero la máquina
de estados (`treatment_transitions.py`) no permite volver nunca a PENDIENTE,
así que esa transición ocurre exactamente una vez por tratamiento -- bajo
una lectura literal, un tratamiento pospuesto y reasignado a un sprint de
otro Q NUNCA podría contar como "entrada" en ambos Qs (la regla de negocio
explícita en §8 del diseño). Se implementa entonces la lectura que sí
satisface esa regla: "Entraron" cuenta cada vez que el `sprint_id` de un
tratamiento cambia a un sprint nuevo (en la creación o en una reasignación
posterior) -- si ese sprint nuevo pertenece al Q, se cuenta como "entrada"
en ese Q. Esto reproduce el caso explícito del encargo (pospuesto de Q2 a
Q3 → cuenta en ambos) sin contradecir la máquina de estados.

Ajuste respecto al diseño ("desglose por severidad"): en vez de resolver
`Finding.severity` vía `finding_id` (que puede ser `NULL` si el finding fue
eliminado, `ondelete=SET NULL`), se usa `priority_band` -- ya está en el
propio tratamiento (capturado al crearlo), evita una dependencia adicional
de `FindingRepository` y no se pierde si el finding deja de existir.
"""
from __future__ import annotations

import calendar
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date

from vulntrack.domain.ports.finding_repository import FindingRepository
from vulntrack.domain.ports.sprint_repository import SprintRepository
from vulntrack.domain.ports.treatment_repository import TreatmentRepository
from vulntrack.domain.entities.vulnerability_treatment import (
    TratamientoVulnerabilidad,
    TreatmentStatus,
    TreatmentStatusHistoryEntry,
)
from vulntrack.domain.services.vuln_identity import identity_key

_QUARTER_MONTHS: dict[int, tuple[int, int]] = {1: (1, 3), 2: (4, 6), 3: (7, 9), 4: (10, 12)}


def _quarter_date_range(anio: int, trimestre: int) -> tuple[date, date]:
    start_month, end_month = _QUARTER_MONTHS[trimestre]
    end_day = calendar.monthrange(anio, end_month)[1]
    return date(anio, start_month, 1), date(anio, end_month, end_day)


@dataclass
class QuarterlyMetricsCore:
    entraron: int = 0
    resueltas: int = 0
    pospuestas: int = 0
    no_cumplidas: int = 0
    en_curso: int = 0
    descartadas: int = 0
    # D4 (iter4-design.md §2.4): findings resueltos (desaparecidos de DT) que
    # NUNCA tuvieron un tratamiento -- categoría separada y mutuamente
    # excluyente de `resueltas` (que sólo cuenta tratamientos con historial de
    # FINALIZADA). Ninguna identidad se cuenta en ambas.
    resueltas_sin_seguimiento: int = 0

    @property
    def pct_cumplimiento(self) -> float | None:
        """`(resueltas + descartadas) / entraron`.

        Retorna `None` si `entraron == 0`: no hay base para medir
        cumplimiento si nada entró al período (evita división por cero).
        """
        if self.entraron == 0:
            return None
        return (self.resueltas + self.descartadas) / self.entraron


@dataclass
class SprintTrend:
    sprint_id: int
    sprint_nombre: str
    core: QuarterlyMetricsCore


@dataclass
class QuarterlyMetrics:
    anio: int
    trimestre: int
    core: QuarterlyMetricsCore
    por_severidad: dict[str, QuarterlyMetricsCore] = field(default_factory=dict)
    por_proyecto: dict[str, QuarterlyMetricsCore] = field(default_factory=dict)
    tendencia_por_sprint: list[SprintTrend] = field(default_factory=list)


_SprintScope = Callable[[int], bool]


def _exact_sprint_scope(sprint_id: int) -> _SprintScope:
    return lambda sid: sid == sprint_id


class QuarterlyMetricsQuery:
    def __init__(
        self,
        treatment_repo: TreatmentRepository,
        sprint_repo: SprintRepository,
        finding_repo: FindingRepository | None = None,
    ) -> None:
        self._treatment_repo = treatment_repo
        self._sprint_repo = sprint_repo
        self._finding_repo = finding_repo

    async def execute(
        self, anio: int, trimestre: int, project_uuid: str | None = None
    ) -> QuarterlyMetrics:
        sprints = await self._sprint_repo.list_all()
        q_sprint_ids = {s.id for s in sprints if s.anio == anio and s.trimestre == trimestre}

        if project_uuid is not None:
            treatments = await self._treatment_repo.list_by_project(project_uuid)
        else:
            treatments = await self._treatment_repo.list_all()
        treatment_by_id = {t.id: t for t in treatments}

        history_rows = await self._treatment_repo.list_history(
            treatment_ids=list(treatment_by_id)
        )
        history_by_treatment: dict[int, list[TreatmentStatusHistoryEntry]] = {}
        for row in history_rows:
            history_by_treatment.setdefault(row.treatment_id, []).append(row)

        core = self._compute_core(
            treatment_by_id, history_by_treatment, lambda sid: sid in q_sprint_ids
        )
        core.resueltas_sin_seguimiento = await self._compute_resueltas_sin_seguimiento(
            anio, trimestre, project_uuid, treatments
        )
        por_severidad = self._bucketed(
            treatment_by_id,
            history_by_treatment,
            lambda sid: sid in q_sprint_ids,
            key_fn=lambda t: t.priority_band.value,
        )
        por_proyecto = self._bucketed(
            treatment_by_id,
            history_by_treatment,
            lambda sid: sid in q_sprint_ids,
            key_fn=lambda t: t.project_uuid,
        )

        tendencia_por_sprint = [
            SprintTrend(
                sprint_id=s.id,
                sprint_nombre=s.nombre,
                core=self._compute_core(
                    treatment_by_id, history_by_treatment, _exact_sprint_scope(s.id)
                ),
            )
            for s in sorted(
                (sp for sp in sprints if sp.id in q_sprint_ids),
                key=lambda sp: sp.fecha_inicio,
            )
        ]

        return QuarterlyMetrics(
            anio=anio,
            trimestre=trimestre,
            core=core,
            por_severidad=por_severidad,
            por_proyecto=por_proyecto,
            tendencia_por_sprint=tendencia_por_sprint,
        )

    async def _compute_resueltas_sin_seguimiento(
        self,
        anio: int,
        trimestre: int,
        project_uuid: str | None,
        treatments: list[TratamientoVulnerabilidad],
    ) -> int:
        """D4: findings resueltos (desaparecidos de DT) en el Q sin NINGUNA
        fila en `vulnerability_treatments` para su identidad -- ni activa ni
        histórica. `treatments` ya trae todo lo alguna vez creado para el
        alcance (proyecto o portafolio), sin filtrar por sprint/estado."""
        if self._finding_repo is None:
            return 0

        date_from, date_to = _quarter_date_range(anio, trimestre)
        resolved_findings = await self._finding_repo.list_resolved_in_range(
            date_from, date_to, project_uuid
        )
        if not resolved_findings:
            return 0

        tracked_identities = {
            (t.project_uuid, t.vuln_key, t.component_name or "", t.component_version or "")
            for t in treatments
        }
        return sum(
            1
            for f in resolved_findings
            if identity_key(f.project_uuid, f.cve_id, f.vuln_id, f.component_name, f.component_version)
            not in tracked_identities
        )

    def _compute_core(
        self,
        treatment_by_id: dict[int, TratamientoVulnerabilidad],
        history_by_treatment: dict[int, list[TreatmentStatusHistoryEntry]],
        in_scope: _SprintScope,
    ) -> QuarterlyMetricsCore:
        entraron_ids: set[int] = set()
        resueltas_ids: set[int] = set()
        pospuestas_ids: set[int] = set()
        no_cumplidas_ids: set[int] = set()
        descartadas_ids: set[int] = set()

        for tid in treatment_by_id:
            prev_sprint_id: int | None = None
            for row in history_by_treatment.get(tid, []):
                if row.sprint_id != prev_sprint_id and in_scope(row.sprint_id):
                    entraron_ids.add(tid)
                prev_sprint_id = row.sprint_id

                if not in_scope(row.sprint_id):
                    continue
                if row.to_status == TreatmentStatus.FINALIZADA:
                    resueltas_ids.add(tid)
                elif row.to_status == TreatmentStatus.POSPUESTA:
                    pospuestas_ids.add(tid)
                elif row.to_status == TreatmentStatus.NO_CUMPLIDA:
                    no_cumplidas_ids.add(tid)
                elif row.to_status == TreatmentStatus.DESCARTADA:
                    descartadas_ids.add(tid)

        en_curso_ids = {
            tid
            for tid, t in treatment_by_id.items()
            if t.estado == TreatmentStatus.EN_CURSO and in_scope(t.sprint_id)
        }

        return QuarterlyMetricsCore(
            entraron=len(entraron_ids),
            resueltas=len(resueltas_ids),
            pospuestas=len(pospuestas_ids),
            no_cumplidas=len(no_cumplidas_ids),
            en_curso=len(en_curso_ids),
            descartadas=len(descartadas_ids),
        )

    def _bucketed(
        self,
        treatment_by_id: dict[int, TratamientoVulnerabilidad],
        history_by_treatment: dict[int, list[TreatmentStatusHistoryEntry]],
        in_scope: _SprintScope,
        *,
        key_fn: Callable[[TratamientoVulnerabilidad], str],
    ) -> dict[str, QuarterlyMetricsCore]:
        ids_by_key: dict[str, set[int]] = {}
        for tid, t in treatment_by_id.items():
            ids_by_key.setdefault(key_fn(t), set()).add(tid)

        return {
            key: self._compute_core(
                {tid: treatment_by_id[tid] for tid in ids},
                {tid: history_by_treatment.get(tid, []) for tid in ids},
                in_scope,
            )
            for key, ids in ids_by_key.items()
        }
