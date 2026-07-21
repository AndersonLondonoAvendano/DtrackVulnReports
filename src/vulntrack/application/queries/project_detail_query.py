"""T-064: Query de detalle de proyecto — métricas + findings priorizados."""
from __future__ import annotations

from dataclasses import dataclass

from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.metric_snapshot import MetricSnapshot
from vulntrack.domain.entities.project import Project
from vulntrack.domain.entities.remediation import RemediationPlan, RemediationTask
from vulntrack.domain.exceptions import ProjectNotFoundError
from vulntrack.domain.ports.finding_repository import FindingRepository
from vulntrack.domain.ports.project_repository import ProjectRepository
from vulntrack.domain.ports.remediation_repository import RemediationRepository
from vulntrack.domain.ports.snapshot_repository import SnapshotRepository
from vulntrack.domain.services.kev_matcher import KevMatcher
from vulntrack.domain.services.prioritization import PrioritizationService, PriorityWeights
from vulntrack.domain.value_objects.priority_score import PriorityScore


@dataclass
class PrioritizedFinding:
    finding: Finding
    score: PriorityScore


@dataclass
class ProjectDetailData:
    project: Project
    current_snapshot: MetricSnapshot | None
    prioritized_findings: list[PrioritizedFinding]
    remediation_plans: list[RemediationPlan]
    open_tasks: list[RemediationTask]


class ProjectDetailQuery:
    def __init__(
        self,
        project_repo: ProjectRepository,
        finding_repo: FindingRepository,
        snapshot_repo: SnapshotRepository,
        remediation_repo: RemediationRepository,
        kev_matcher: KevMatcher,
        weights: PriorityWeights | None = None,
    ) -> None:
        self._project_repo = project_repo
        self._finding_repo = finding_repo
        self._snapshot_repo = snapshot_repo
        self._remediation_repo = remediation_repo
        self._kev_matcher = kev_matcher
        self._svc = PrioritizationService(weights)

    async def execute(self, project_uuid: str) -> ProjectDetailData:
        project = await self._project_repo.get_by_uuid(project_uuid)
        if project is None:
            raise ProjectNotFoundError(project_uuid)

        from datetime import date

        current_snapshot = await self._snapshot_repo.get_closest_before(
            project_uuid, date.today()
        )
        findings = await self._finding_repo.list_by_project(project_uuid)

        prioritized = sorted(
            [
                PrioritizedFinding(
                    finding=f,
                    score=self._svc.score(f, self._kev_matcher.is_in_kev(f.cve_id, f.vuln_id)),
                )
                for f in findings
            ],
            key=lambda pf: pf.score.value,
            reverse=True,
        )

        plans = await self._remediation_repo.list_plans_by_project(project_uuid)
        open_tasks: list[RemediationTask] = []
        for plan in plans:
            tasks = await self._remediation_repo.list_tasks_by_plan(plan.id)
            open_tasks.extend(tasks)

        return ProjectDetailData(
            project=project,
            current_snapshot=current_snapshot,
            prioritized_findings=prioritized,
            remediation_plans=plans,
            open_tasks=open_tasks,
        )
