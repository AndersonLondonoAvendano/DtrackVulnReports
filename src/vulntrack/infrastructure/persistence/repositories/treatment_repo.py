from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any, Literal

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.vulnerability_treatment import (
    TratamientoVulnerabilidad,
    TreatmentStatus,
    TreatmentStatusHistoryEntry,
)
from vulntrack.domain.services.treatment_transitions import ACTIVE_TREATMENT_STATES
from vulntrack.domain.value_objects.priority_score import PriorityBand
from vulntrack.infrastructure.persistence.mappers import (
    orm_to_finding,
    orm_to_history_entry,
    orm_to_treatment,
)
from vulntrack.infrastructure.persistence.orm_models import (
    FindingORM,
    TreatmentStatusHistoryORM,
    VulnerabilityTreatmentORM,
)

_TERMINAL_HISTORY_STATES = {TreatmentStatus.FINALIZADA.value, TreatmentStatus.DESCARTADA.value}


class SqliteTreatmentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        project_uuid: str,
        vuln_key: str,
        cve_id: str | None,
        finding_id: int | None,
        plan_id: int | None,
        sprint_id: int,
        responsable: str | None,
        priority_band: PriorityBand,
        fecha_objetivo: date | None = None,
        component_name: str | None = None,
        component_version: str | None = None,
    ) -> TratamientoVulnerabilidad:
        now = datetime.now(UTC)
        row = VulnerabilityTreatmentORM(
            project_uuid=project_uuid,
            vuln_key=vuln_key,
            cve_id=cve_id,
            finding_id=finding_id,
            plan_id=plan_id,
            sprint_id=sprint_id,
            responsable=responsable,
            estado=TreatmentStatus.PENDIENTE.value,
            priority_band=priority_band.value,
            fecha_creacion=now,
            fecha_objetivo=fecha_objetivo,
            component_name=component_name,
            component_version=component_version,
            created_at=now,
            updated_at=now,
        )
        self._session.add(row)
        await self._session.flush()
        return orm_to_treatment(row)

    async def get_by_id(self, treatment_id: int) -> TratamientoVulnerabilidad | None:
        row = await self._session.get(VulnerabilityTreatmentORM, treatment_id)
        return orm_to_treatment(row) if row is not None else None

    async def remove(self, treatment_id: int) -> Literal["deleted", "unlinked"]:
        """Delete híbrido (T-E011): si el tratamiento nunca llegó a un estado
        terminal (FINALIZADA/DESCARTADA), se borra físicamente junto con su
        historial; si ya llegó, se desvincula (`activo_en_plan=False`,
        `plan_id=None`) preservando su historial para las métricas D4."""
        row = await self._session.get(VulnerabilityTreatmentORM, treatment_id)
        if row is None:
            raise ValueError(f"VulnerabilityTreatment {treatment_id} not found")

        history_result = await self._session.execute(
            select(TreatmentStatusHistoryORM.to_status).where(
                TreatmentStatusHistoryORM.treatment_id == treatment_id
            )
        )
        reached_terminal = any(
            to_status in _TERMINAL_HISTORY_STATES for to_status in history_result.scalars().all()
        )

        if not reached_terminal:
            await self._session.delete(row)
            await self._session.flush()
            return "deleted"

        row.activo_en_plan = False
        row.plan_id = None
        row.updated_at = datetime.now(UTC)
        await self._session.flush()
        return "unlinked"

    async def update(self, treatment_id: int, **fields: Any) -> TratamientoVulnerabilidad:
        row = await self._session.get(VulnerabilityTreatmentORM, treatment_id)
        if row is None:
            raise ValueError(f"VulnerabilityTreatment {treatment_id} not found")

        updatable = {
            "sprint_id",
            "responsable",
            "estado",
            "fecha_objetivo",
            "fecha_cierre",
            "notas",
            "motivo",
            "recurrence_flag",
            "recurrence_count",
            "last_recurrence_at",
            "finalizacion_subtipo",
            "activo_en_plan",
            "plan_id",
        }
        for key, value in fields.items():
            if key not in updatable:
                continue
            if key == "estado" and isinstance(value, TreatmentStatus):
                row.estado = value.value
            else:
                setattr(row, key, value)
        row.updated_at = datetime.now(UTC)
        await self._session.flush()
        return orm_to_treatment(row)

    async def list_available_for_project(self, project_uuid: str) -> list[Finding]:
        # D1 (iter4-design.md): la identidad incluye componente + versión, no
        # sólo vuln_key -- el mismo CVE en dos componentes distintos es
        # "disponible" independientemente uno de otro. `activo_en_plan=False`
        # (delete híbrido, T-E011) tampoco cuenta como "tomado".
        active_states = tuple(ACTIVE_TREATMENT_STATES)
        stmt = (
            select(FindingORM)
            .outerjoin(
                VulnerabilityTreatmentORM,
                and_(
                    VulnerabilityTreatmentORM.project_uuid == FindingORM.project_uuid,
                    VulnerabilityTreatmentORM.vuln_key
                    == func.coalesce(FindingORM.cve_id, FindingORM.vuln_id),
                    VulnerabilityTreatmentORM.component_name == FindingORM.component_name,
                    func.coalesce(VulnerabilityTreatmentORM.component_version, "")
                    == func.coalesce(FindingORM.component_version, ""),
                    VulnerabilityTreatmentORM.estado.in_(active_states),
                    VulnerabilityTreatmentORM.activo_en_plan.is_(True),
                ),
            )
            .where(
                FindingORM.project_uuid == project_uuid,
                FindingORM.suppressed.is_(False),
                FindingORM.estado_ciclo_vida == "ACTIVA",
                VulnerabilityTreatmentORM.id.is_(None),
            )
        )
        result = await self._session.execute(stmt)
        return [orm_to_finding(r) for r in result.scalars().all()]

    async def list_by_project(
        self,
        project_uuid: str,
        *,
        sprint_id: int | None = None,
        estado: TreatmentStatus | None = None,
    ) -> list[TratamientoVulnerabilidad]:
        stmt = select(VulnerabilityTreatmentORM).where(
            VulnerabilityTreatmentORM.project_uuid == project_uuid
        )
        if sprint_id is not None:
            stmt = stmt.where(VulnerabilityTreatmentORM.sprint_id == sprint_id)
        if estado is not None:
            stmt = stmt.where(VulnerabilityTreatmentORM.estado == estado.value)
        result = await self._session.execute(stmt)
        return [orm_to_treatment(r) for r in result.scalars().all()]

    async def list_by_sprint(self, sprint_id: int) -> list[TratamientoVulnerabilidad]:
        result = await self._session.execute(
            select(VulnerabilityTreatmentORM).where(
                VulnerabilityTreatmentORM.sprint_id == sprint_id
            )
        )
        return [orm_to_treatment(r) for r in result.scalars().all()]

    async def list_all(
        self,
        *,
        sprint_id: int | None = None,
        estado: TreatmentStatus | None = None,
    ) -> list[TratamientoVulnerabilidad]:
        stmt = select(VulnerabilityTreatmentORM)
        if sprint_id is not None:
            stmt = stmt.where(VulnerabilityTreatmentORM.sprint_id == sprint_id)
        if estado is not None:
            stmt = stmt.where(VulnerabilityTreatmentORM.estado == estado.value)
        result = await self._session.execute(stmt)
        return [orm_to_treatment(r) for r in result.scalars().all()]

    async def append_history(
        self,
        treatment_id: int,
        *,
        from_status: TreatmentStatus | None,
        to_status: TreatmentStatus,
        sprint_id: int,
        note: str | None = None,
    ) -> TreatmentStatusHistoryEntry:
        row = TreatmentStatusHistoryORM(
            treatment_id=treatment_id,
            from_status=from_status.value if from_status else None,
            to_status=to_status.value,
            sprint_id=sprint_id,
            changed_at=datetime.now(UTC),
            note=note,
        )
        self._session.add(row)
        await self._session.flush()
        return orm_to_history_entry(row)

    async def list_history(
        self, treatment_ids: list[int] | None = None
    ) -> list[TreatmentStatusHistoryEntry]:
        if treatment_ids is not None and not treatment_ids:
            return []
        stmt = select(TreatmentStatusHistoryORM).order_by(TreatmentStatusHistoryORM.id)
        if treatment_ids is not None:
            stmt = stmt.where(TreatmentStatusHistoryORM.treatment_id.in_(treatment_ids))
        result = await self._session.execute(stmt)
        return [orm_to_history_entry(r) for r in result.scalars().all()]
