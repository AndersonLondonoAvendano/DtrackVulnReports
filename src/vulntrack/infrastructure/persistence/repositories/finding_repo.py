from __future__ import annotations

from datetime import UTC, date, datetime

from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from vulntrack.domain.entities.finding import Finding, FindingLifecycleState
from vulntrack.infrastructure.persistence.mappers import orm_to_finding
from vulntrack.infrastructure.persistence.orm_models import FindingORM


class SqliteFindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert_batch(self, findings: list[Finding]) -> None:
        now = datetime.now(UTC)
        for f in findings:
            stmt = sqlite_insert(FindingORM).values(
                project_uuid=f.project_uuid,
                dt_finding_uuid=f.dt_finding_uuid,
                component_name=f.component_name,
                component_version=f.component_version,
                component_group=f.component_group,
                vuln_id=f.vuln_id,
                vuln_source=f.vuln_source,
                severity=f.severity.value,
                cve_id=f.cve_id,
                cvss_v3_base_score=f.cvss_v3_base_score,
                epss_score=f.epss_score,
                epss_percentile=f.epss_percentile,
                attributed_on=f.attributed_on,
                suppressed=f.suppressed,
                last_synced_at=f.last_synced_at,
                primera_deteccion_at=f.last_synced_at,
                ultima_vista_at=f.last_synced_at,
                created_at=now,
                updated_at=now,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["project_uuid", "dt_finding_uuid"],
                set_={
                    "component_name": stmt.excluded.component_name,
                    "component_version": stmt.excluded.component_version,
                    "component_group": stmt.excluded.component_group,
                    "vuln_id": stmt.excluded.vuln_id,
                    "vuln_source": stmt.excluded.vuln_source,
                    "severity": stmt.excluded.severity,
                    "cve_id": stmt.excluded.cve_id,
                    "cvss_v3_base_score": stmt.excluded.cvss_v3_base_score,
                    "epss_score": stmt.excluded.epss_score,
                    "epss_percentile": stmt.excluded.epss_percentile,
                    "attributed_on": stmt.excluded.attributed_on,
                    "suppressed": stmt.excluded.suppressed,
                    "last_synced_at": stmt.excluded.last_synced_at,
                    "ultima_vista_at": stmt.excluded.ultima_vista_at,
                    "updated_at": stmt.excluded.updated_at,
                },
            )
            await self._session.execute(stmt)

    async def list_by_project(
        self, project_uuid: str, suppress_suppressed: bool = True
    ) -> list[Finding]:
        stmt = select(FindingORM).where(FindingORM.project_uuid == project_uuid)
        if suppress_suppressed:
            stmt = stmt.where(FindingORM.suppressed.is_(False))
        result = await self._session.execute(stmt)
        return [orm_to_finding(r) for r in result.scalars().all()]

    async def list_all_active(
        self,
        min_cvss: float | None = None,
        min_epss: float | None = None,
    ) -> list[Finding]:
        stmt = select(FindingORM).where(FindingORM.suppressed.is_(False))
        if min_cvss is not None:
            stmt = stmt.where(FindingORM.cvss_v3_base_score >= min_cvss)
        if min_epss is not None:
            stmt = stmt.where(FindingORM.epss_score >= min_epss)
        result = await self._session.execute(stmt)
        return [orm_to_finding(r) for r in result.scalars().all()]

    async def get_new_in_range(self, date_from: date, date_to: date) -> list[Finding]:
        dt_from = datetime(date_from.year, date_from.month, date_from.day, 0, 0, 0)
        dt_to = datetime(date_to.year, date_to.month, date_to.day, 23, 59, 59)
        result = await self._session.execute(
            select(FindingORM).where(
                FindingORM.attributed_on >= dt_from,
                FindingORM.attributed_on <= dt_to,
            )
        )
        return [orm_to_finding(r) for r in result.scalars().all()]

    async def list_by_lifecycle_state(
        self, project_uuid: str, estado: FindingLifecycleState
    ) -> list[Finding]:
        result = await self._session.execute(
            select(FindingORM).where(
                FindingORM.project_uuid == project_uuid,
                FindingORM.estado_ciclo_vida == estado.value,
            )
        )
        return [orm_to_finding(r) for r in result.scalars().all()]

    async def mark_resolved(self, finding_id: int, resuelta_at: datetime) -> Finding:
        row = await self._session.get(FindingORM, finding_id)
        if row is None:
            raise ValueError(f"Finding {finding_id} not found")
        row.estado_ciclo_vida = FindingLifecycleState.RESUELTA.value
        row.resuelta_at = resuelta_at
        row.updated_at = datetime.now(UTC)
        await self._session.flush()
        return orm_to_finding(row)

    async def list_resolved_in_range(
        self, date_from: date, date_to: date, project_uuid: str | None = None
    ) -> list[Finding]:
        dt_from = datetime(date_from.year, date_from.month, date_from.day, 0, 0, 0)
        dt_to = datetime(date_to.year, date_to.month, date_to.day, 23, 59, 59)
        stmt = select(FindingORM).where(
            FindingORM.estado_ciclo_vida == FindingLifecycleState.RESUELTA.value,
            FindingORM.resuelta_at >= dt_from,
            FindingORM.resuelta_at <= dt_to,
        )
        if project_uuid is not None:
            stmt = stmt.where(FindingORM.project_uuid == project_uuid)
        result = await self._session.execute(stmt)
        return [orm_to_finding(r) for r in result.scalars().all()]

    async def mark_reactivated(self, finding_id: int, reaparicion_at: datetime) -> Finding:
        row = await self._session.get(FindingORM, finding_id)
        if row is None:
            raise ValueError(f"Finding {finding_id} not found")
        row.estado_ciclo_vida = FindingLifecycleState.ACTIVA.value
        row.resuelta_at = None
        row.es_reincidente = True
        row.reaparicion_count += 1
        row.ultima_reaparicion_at = reaparicion_at
        row.updated_at = datetime.now(UTC)
        await self._session.flush()
        return orm_to_finding(row)
