"""T-063: Query de dashboard — agrega KPIs del portafolio."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.project import Project
from vulntrack.domain.entities.remediation import TaskStatus
from vulntrack.domain.ports.finding_repository import FindingRepository
from vulntrack.domain.ports.kev_repository import KevRepository
from vulntrack.domain.ports.project_repository import ProjectRepository
from vulntrack.domain.ports.remediation_repository import RemediationRepository
from vulntrack.domain.value_objects.severity import Severity


class AppSettingsPort(Protocol):
    async def get(self) -> object: ...


@dataclass
class TaskSummary:
    total: int = 0
    pending: int = 0
    in_progress: int = 0
    completed: int = 0


@dataclass
class DashboardData:
    total_vigentes: int
    vigentes_por_severidad: dict[Severity, int]
    proyectos_en_cero: int
    proyectos_con_criticas: int
    last_sync_at: datetime | None
    kev_hits_count: int
    total_proyectos: int
    tasks_summary: TaskSummary = field(default_factory=TaskSummary)


class DashboardQuery:
    def __init__(
        self,
        project_repo: ProjectRepository,
        finding_repo: FindingRepository,
        kev_repo: KevRepository,
        remediation_repo: RemediationRepository,
        last_sync_at: datetime | None = None,
    ) -> None:
        self._project_repo = project_repo
        self._finding_repo = finding_repo
        self._kev_repo = kev_repo
        self._remediation_repo = remediation_repo
        self._last_sync_at = last_sync_at

    async def execute(self) -> DashboardData:
        projects: list[Project] = await self._project_repo.list_all()
        findings: list[Finding] = await self._finding_repo.list_all_active()
        kev_meta = await self._kev_repo.get_catalog_meta()

        # Aggregate severity counts
        vigentes_por_severidad: dict[Severity, int] = dict.fromkeys(Severity, 0)
        for f in findings:
            vigentes_por_severidad[f.severity] = (
                vigentes_por_severidad.get(f.severity, 0) + 1
            )
        total_vigentes = sum(vigentes_por_severidad.values())

        # Projects with zero active findings
        projects_with_findings: set[str] = {f.project_uuid for f in findings}
        proyectos_en_cero = sum(
            1 for p in projects if p.uuid not in projects_with_findings
        )

        # Projects with at least one CRITICAL finding
        projects_with_critical: set[str] = {
            f.project_uuid
            for f in findings
            if f.severity == Severity.CRITICAL
        }
        proyectos_con_criticas = len(projects_with_critical)

        # KEV hits count: findings cuyo CVE canónico (o vuln_id como fallback) está en KEV
        all_kev = await self._kev_repo.list_all()
        kev_ids = {e.cve_id.upper() for e in all_kev}
        kev_hits_count = sum(1 for f in findings if (f.cve_id or f.vuln_id).upper() in kev_ids)

        # Resumen de tareas de remediación (todos los planes, todos los proyectos)
        tasks = await self._remediation_repo.list_all_tasks()
        tasks_summary = TaskSummary(
            total=len(tasks),
            pending=sum(1 for t in tasks if t.status == TaskStatus.PENDING),
            in_progress=sum(1 for t in tasks if t.status == TaskStatus.IN_PROGRESS),
            completed=sum(1 for t in tasks if t.status == TaskStatus.COMPLETED),
        )

        return DashboardData(
            total_vigentes=total_vigentes,
            vigentes_por_severidad=vigentes_por_severidad,
            proyectos_en_cero=proyectos_en_cero,
            proyectos_con_criticas=proyectos_con_criticas,
            last_sync_at=self._last_sync_at,
            kev_hits_count=kev_hits_count,
            total_proyectos=len(projects),
            tasks_summary=tasks_summary,
        )
