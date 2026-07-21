"""T-E013: reconciliación de sync (Bloque B, iter4-design.md §2.2).

DT sólo refleja el estado *actual* del portafolio -- cada sync trae la lista
completa de hallazgos activos, nunca "elimina" nada del lado nuestro. Este
reconciliador es quien traduce esa foto instantánea en una transición de
ciclo de vida por identidad D1:

- NUEVA: identidad no vista antes en el proyecto -> se inserta (ACTIVA).
- SE_MANTIENE: identidad ya ACTIVA y sigue en el sync -> sólo se refrescan
  sus campos (severidad/CVSS/EPSS) y `ultima_vista_at`.
- DESAPARECIÓ: identidad estaba ACTIVA y ya no aparece en el sync -> RESUELTA
  (D2: inmediato, sin período de gracia). La vulnerabilidad NUNCA se borra.
- REAPARECIÓ: identidad estaba RESUELTA y vuelve a aparecer -> ACTIVA de
  nuevo, marcada `es_reincidente`, con contador incrementado.

Nada de esto borra filas de `findings` -- RESUELTA es un estado, no una
eliminación (D2: "RESUELTA es intocable").
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from vulntrack.domain.entities.finding import Finding, FindingLifecycleState
from vulntrack.domain.ports.finding_repository import FindingRepository
from vulntrack.domain.services.vuln_identity import identity_key


@dataclass
class ReconciliationSummary:
    nuevas: int = 0
    se_mantienen: int = 0
    resueltas: int = 0
    reincidentes: int = 0
    # Identidades D1 (no ids de fila) de los findings DESAPARECIÓ/REAPARECIÓ en
    # esta corrida -- Bloque B: el disparador de D3 para tratamientos las usa
    # para decidir auto-finalización/reapertura sin volver a comparar fechas.
    desaparecidas: list[tuple[str, str, str, str]] = field(default_factory=list)
    reaparecidas: list[tuple[str, str, str, str]] = field(default_factory=list)
    # Todas las identidades confirmadas activas en ESTA corrida (NUEVA +
    # SE_MANTIENE + REAPARECIÓ) -- más amplio que `reaparecidas`. Un
    # tratamiento FINALIZADA cuya identidad sigue confirmándose activa debe
    # reabrirse aunque su finding nunca haya pasado por RESUELTA (p. ej. el
    # usuario cerró el tratamiento pero DT nunca dejó de ver la vulnerabilidad
    # -- mismo comportamiento que T-D023 antes de que existiera el ciclo de
    # vida explícito de Finding).
    activas_en_sync: list[tuple[str, str, str, str]] = field(default_factory=list)


class FindingReconciler:
    def __init__(self, finding_repo: FindingRepository) -> None:
        self._finding_repo = finding_repo

    async def reconcile(
        self, project_uuid: str, dt_findings: list[Finding], synced_at: datetime
    ) -> ReconciliationSummary:
        existing = await self._finding_repo.list_by_project(project_uuid, suppress_suppressed=False)
        existing_by_identity = {_identity(f): f for f in existing}

        incoming_identities = {_identity(f) for f in dt_findings}

        summary = ReconciliationSummary()
        summary.activas_en_sync = list(incoming_identities)
        for identity in incoming_identities:
            match = existing_by_identity.get(identity)
            if match is None:
                summary.nuevas += 1
            elif match.estado_ciclo_vida == FindingLifecycleState.RESUELTA:
                summary.reaparecidas.append(identity)
            else:
                summary.se_mantienen += 1

        # Upsert real de los hallazgos entrantes: inserta NUEVAs, refresca
        # campos de SE_MANTIENE/REAPARECIÓ (severidad/CVSS/EPSS/ultima_vista_at).
        if dt_findings:
            await self._finding_repo.upsert_batch(dt_findings)

        for identity in summary.reaparecidas:
            await self._finding_repo.mark_reactivated(existing_by_identity[identity].id, synced_at)
        summary.reincidentes = len(summary.reaparecidas)

        for identity, finding in existing_by_identity.items():
            if (
                finding.estado_ciclo_vida == FindingLifecycleState.ACTIVA
                and identity not in incoming_identities
            ):
                await self._finding_repo.mark_resolved(finding.id, synced_at)
                summary.desaparecidas.append(identity)
        summary.resueltas = len(summary.desaparecidas)

        return summary


def _identity(f: Finding) -> tuple[str, str, str, str]:
    return identity_key(f.project_uuid, f.cve_id, f.vuln_id, f.component_name, f.component_version)
