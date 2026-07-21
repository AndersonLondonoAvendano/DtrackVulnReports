"""T-D023/T-E015: reconciliador de tratamientos ante cambios de ciclo de vida
de findings (D3, iter3-design.md §4.4 / iter4-design.md §2.3).

El disparador ya no es una comparación de fechas (`last_synced_at`) sino las
identidades DESAPARECIÓ/confirmadas-activas que produce `FindingReconciler` en
la misma corrida de sync -- una sola fuente de verdad para "la vulnerabilidad
sigue/dejó de estar activa en DT".

- Identidad confirmada activa en este sync + tratamiento FINALIZADA -> se
  reabre el MISMO tratamiento (mismo comportamiento que T-D023, sólo cambia
  el disparador; no importa si el finding pasó por RESUELTA o nunca dejó de
  estar ACTIVA -- lo que importa es que DT lo sigue confirmando).
- DESAPARECIÓ + tratamiento en PENDIENTE/EN_CURSO/POSPUESTA/NO_CUMPLIDA ->
  auto-finalización (D3): `FINALIZADA` con `finalizacion_subtipo="AUSENCIA_DT"`,
  distinguible de una finalización manual.
- DESAPARECIÓ + tratamiento DESCARTADA o ya FINALIZADA -> sin cambios
  (decisión confirmada: no se reabre ni se re-finaliza un descarte).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from vulntrack.application.sync.finding_reconciler import ReconciliationSummary
from vulntrack.domain.entities.vulnerability_treatment import TratamientoVulnerabilidad, TreatmentStatus
from vulntrack.domain.ports.treatment_repository import TreatmentRepository

_AUTO_FINALIZE_FROM_STATES = frozenset(
    {
        TreatmentStatus.PENDIENTE,
        TreatmentStatus.EN_CURSO,
        TreatmentStatus.POSPUESTA,
        TreatmentStatus.NO_CUMPLIDA,
    }
)


@dataclass
class TreatmentReconciliationResult:
    auto_finalizados: int = 0
    reabiertos: int = 0


class TreatmentSyncReconciler:
    def __init__(self, treatment_repo: TreatmentRepository, finding_repo: object | None = None) -> None:
        # `finding_repo` se conserva como parámetro opcional por compatibilidad
        # de wiring (DI); ya no se usa -- las identidades DESAPARECIÓ/REAPARECIÓ
        # llegan pre-calculadas desde `FindingReconciler` (T-E013).
        self._treatment_repo = treatment_repo

    async def reconcile_from_summary(
        self, project_uuid: str, summary: ReconciliationSummary, synced_at: datetime
    ) -> TreatmentReconciliationResult:
        if not summary.desaparecidas and not summary.activas_en_sync:
            return TreatmentReconciliationResult()

        treatments = await self._treatment_repo.list_by_project(project_uuid)
        by_identity: dict[tuple[str, str, str, str], TratamientoVulnerabilidad] = {
            _treatment_identity(t): t for t in treatments if t.activo_en_plan
        }

        result = TreatmentReconciliationResult()

        for identity in summary.desaparecidas:
            treatment = by_identity.get(identity)
            if treatment is None or treatment.estado not in _AUTO_FINALIZE_FROM_STATES:
                continue
            await self._treatment_repo.update(
                treatment.id,
                estado=TreatmentStatus.FINALIZADA,
                fecha_cierre=synced_at,
                finalizacion_subtipo="AUSENCIA_DT",
            )
            await self._treatment_repo.append_history(
                treatment.id,
                from_status=treatment.estado,
                to_status=TreatmentStatus.FINALIZADA,
                sprint_id=treatment.sprint_id,
                note=(
                    "Resuelta (ausencia en DT) — sync del "
                    f"{synced_at:%Y-%m-%d %H:%M}"
                ),
            )
            result.auto_finalizados += 1

        for identity in summary.activas_en_sync:
            treatment = by_identity.get(identity)
            if treatment is None or treatment.estado != TreatmentStatus.FINALIZADA:
                continue
            await self._treatment_repo.update(
                treatment.id,
                estado=TreatmentStatus.EN_CURSO,
                recurrence_flag=True,
                recurrence_count=treatment.recurrence_count + 1,
                last_recurrence_at=synced_at,
                fecha_cierre=None,
            )
            await self._treatment_repo.append_history(
                treatment.id,
                from_status=TreatmentStatus.FINALIZADA,
                to_status=TreatmentStatus.EN_CURSO,
                sprint_id=treatment.sprint_id,
                note=(
                    "Reabierto automáticamente: la vulnerabilidad sigue activa en "
                    f"DT tras la sincronización del {synced_at:%Y-%m-%d %H:%M}"
                ),
            )
            result.reabiertos += 1

        return result


def _treatment_identity(t: TratamientoVulnerabilidad) -> tuple[str, str, str, str]:
    return (t.project_uuid, t.vuln_key, t.component_name or "", t.component_version or "")
