"""T-065: Caso de uso BuildReportData — ensambla ReportData desde repositorios."""
from __future__ import annotations

import logging
from datetime import UTC, datetime

from vulntrack.application.queries.quarterly_metrics_query import QuarterlyMetricsQuery
from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.metric_snapshot import MetricSnapshot
from vulntrack.domain.entities.project import Project
from vulntrack.domain.ports.finding_repository import FindingRepository
from vulntrack.domain.ports.kev_repository import KevRepository
from vulntrack.domain.ports.project_repository import ProjectRepository
from vulntrack.domain.ports.snapshot_repository import SnapshotRepository
from vulntrack.domain.ports.sprint_repository import SprintRepository
from vulntrack.domain.ports.treatment_repository import TreatmentRepository
from vulntrack.domain.services.advance_calculator import AdvanceCalculator, AdvanceResult
from vulntrack.domain.services.kev_matcher import KevMatcher
from vulntrack.domain.services.prioritization import PrioritizationService, PriorityWeights
from vulntrack.domain.services.quarter import quarter_of
from vulntrack.domain.value_objects.date_range import DateRange
from vulntrack.domain.value_objects.priority_score import PriorityBand
from vulntrack.domain.value_objects.severity import Severity
from vulntrack.infrastructure.reports.chart_builder import (
    EvolutionRow,
    PrioritizedFindingRow,
    ProjectRow,
    QuarterlyProgressData,
    QuarterlySprintTrendRow,
    ReportData,
)

logger = logging.getLogger(__name__)

_TOP_N_PRIORITIZED = 50


class BuildReportDataUseCase:
    def __init__(
        self,
        project_repo: ProjectRepository,
        finding_repo: FindingRepository,
        snapshot_repo: SnapshotRepository,
        kev_repo: KevRepository,
        treatment_repo: TreatmentRepository | None = None,
        sprint_repo: SprintRepository | None = None,
        weights: PriorityWeights | None = None,
        author: str = "VulnTrack Reports",
    ) -> None:
        self._project_repo = project_repo
        self._finding_repo = finding_repo
        self._snapshot_repo = snapshot_repo
        self._kev_repo = kev_repo
        self._treatment_repo = treatment_repo
        self._sprint_repo = sprint_repo
        self._weights = weights
        self._author = author
        self._calc = AdvanceCalculator()
        self._svc = PrioritizationService(weights)

    async def execute(
        self,
        date_range: DateRange,
        period_label: str,
        project_uuids: list[str] | None = None,
    ) -> ReportData:
        # Load all projects
        all_projects = await self._project_repo.list_all()
        if project_uuids is not None:
            projects = [p for p in all_projects if p.uuid in set(project_uuids)]
        else:
            projects = all_projects

        # Build KEV matcher
        kev_entries = await self._kev_repo.list_all()
        kev_matcher = KevMatcher(kev_entries)

        # Load all active findings (optionally filtered by project)
        all_findings = await self._finding_repo.list_all_active()
        if project_uuids is not None:
            uuids_set = set(project_uuids)
            all_findings = [f for f in all_findings if f.project_uuid in uuids_set]

        # New findings in range
        new_findings_in_range = await self._finding_repo.get_new_in_range(
            date_range.date_from, date_range.date_to
        )
        if project_uuids is not None:
            uuids_set = set(project_uuids)
            new_findings_in_range = [
                f for f in new_findings_in_range if f.project_uuid in uuids_set
            ]

        # Portfolio-level severity distribution (vigentes)
        portfolio_metrics: dict[Severity, int] = dict.fromkeys(Severity, 0)
        for f in all_findings:
            portfolio_metrics[f.severity] += 1

        # New findings severity distribution
        new_portfolio_metrics: dict[Severity, int] = dict.fromkeys(Severity, 0)
        for f in new_findings_in_range:
            new_portfolio_metrics[f.severity] += 1

        # Per-project calculations
        project_rows: list[ProjectRow] = []
        evolution_rows: list[EvolutionRow] = []
        total_tratadas = 0

        for project in projects:
            proj_findings = [f for f in all_findings if f.project_uuid == project.uuid]
            proj_new = [f for f in new_findings_in_range if f.project_uuid == project.uuid]

            sev_counts: dict[Severity, int] = dict.fromkeys(Severity, 0)
            for f in proj_findings:
                sev_counts[f.severity] += 1

            inicio_snap = await self._snapshot_repo.get_closest_before(
                project.uuid, date_range.date_from
            )
            actual_snap = await self._snapshot_repo.get_closest_before(
                project.uuid, date_range.date_to
            )

            # Current metrics snapshot (for risk_score)
            risk_score = actual_snap.risk_score if actual_snap else 0.0
            total_proj = sum(sev_counts.values())

            project_rows.append(
                ProjectRow(
                    name=project.name,
                    critical=sev_counts[Severity.CRITICAL],
                    high=sev_counts[Severity.HIGH],
                    medium=sev_counts[Severity.MEDIUM],
                    low=sev_counts[Severity.LOW],
                    unassigned=sev_counts[Severity.UNASSIGNED],
                    total=total_proj,
                    risk_score=risk_score,
                )
            )

            # Evolution
            if inicio_snap is not None:
                try:
                    adv: AdvanceResult = self._calc.calculate(
                        project, inicio_snap, actual_snap, proj_new
                    )
                    total_tratadas += adv.tratadas
                    evolution_rows.append(
                        EvolutionRow(
                            name=project.name,
                            inicio=inicio_snap.total_assigned(),
                            actual=actual_snap.total_assigned() if actual_snap else 0,
                            variacion=adv.variacion_total,
                            tratadas=adv.tratadas,
                        )
                    )
                except Exception as exc:
                    logger.warning(
                        "build_report_data_advance_calc_failed project=%s error=%s",
                        project.name,
                        exc,
                    )

        # Prioritized findings (top N)
        prioritized_items = sorted(
            [
                (f, self._svc.score(f, kev_matcher.is_in_kev(f.cve_id, f.vuln_id)))
                for f in all_findings
            ],
            key=lambda x: x[1].value,
            reverse=True,
        )[:_TOP_N_PRIORITIZED]

        prioritized_findings: list[PrioritizedFindingRow] = [
            _to_prioritized_row(f, score, _project_name(projects, f.project_uuid))
            for f, score in prioritized_items
        ]
        kev_hits: list[PrioritizedFindingRow] = [
            row for row in prioritized_findings if row.is_kev
        ]

        # Aggregate portfolio risk score (weighted average by finding count)
        risk_score_portfolio = (
            sum(r.risk_score * r.total for r in project_rows)
            / max(sum(r.total for r in project_rows), 1)
        )

        quarterly_progress = await self._build_quarterly_progress(date_range, project_uuids)

        return ReportData(
            period_label=period_label,
            date_from=date_range.date_from,
            date_to=date_range.date_to,
            generated_at=datetime.now(UTC),
            author=self._author,
            total_vigentes=sum(portfolio_metrics.values()),
            total_nuevas=sum(new_portfolio_metrics.values()),
            total_tratadas=total_tratadas,
            risk_score_portfolio=risk_score_portfolio,
            portfolio_metrics=portfolio_metrics,
            new_portfolio_metrics=new_portfolio_metrics,
            project_rows=project_rows,
            evolution_rows=evolution_rows,
            prioritized_findings=prioritized_findings,
            kev_hits=kev_hits,
            quarterly_progress=quarterly_progress,
        )

    async def _build_quarterly_progress(
        self, date_range: DateRange, project_uuids: list[str] | None
    ) -> QuarterlyProgressData | None:
        """T-D048: sección opcional -- `None` si no se wireó sprint/treatment
        repo, o si no hay ningún tratamiento para el Q/proyecto del reporte."""
        if self._treatment_repo is None or self._sprint_repo is None:
            return None

        anio, trimestre = quarter_of(date_range.date_to)
        project_uuid = (
            project_uuids[0] if project_uuids is not None and len(project_uuids) == 1 else None
        )
        try:
            metrics = await QuarterlyMetricsQuery(
                treatment_repo=self._treatment_repo, sprint_repo=self._sprint_repo
            ).execute(anio, trimestre, project_uuid=project_uuid)
        except Exception as exc:
            logger.warning("build_report_data_quarterly_progress_failed error=%s", exc)
            return None

        if metrics.core.entraron == 0 and not metrics.tendencia_por_sprint:
            return None

        return QuarterlyProgressData(
            anio=metrics.anio,
            trimestre=metrics.trimestre,
            entraron=metrics.core.entraron,
            resueltas=metrics.core.resueltas,
            pospuestas=metrics.core.pospuestas,
            no_cumplidas=metrics.core.no_cumplidas,
            en_curso=metrics.core.en_curso,
            descartadas=metrics.core.descartadas,
            pct_cumplimiento=metrics.core.pct_cumplimiento,
            tendencia_por_sprint=[
                QuarterlySprintTrendRow(
                    sprint_nombre=t.sprint_nombre,
                    entraron=t.core.entraron,
                    resueltas=t.core.resueltas,
                    pospuestas=t.core.pospuestas,
                    no_cumplidas=t.core.no_cumplidas,
                    en_curso=t.core.en_curso,
                    descartadas=t.core.descartadas,
                )
                for t in metrics.tendencia_por_sprint
            ],
        )


def _project_name(projects: list[Project], uuid: str) -> str:
    for p in projects:
        if p.uuid == uuid:
            return p.name
    return uuid


def _to_prioritized_row(
    f: Finding, score: object, project_name: str
) -> PrioritizedFindingRow:
    from vulntrack.domain.value_objects.priority_score import PriorityScore

    ps: PriorityScore = score  # type: ignore[assignment]
    return PrioritizedFindingRow(
        vuln_id=f.vuln_id,
        component_name=f.component_name,
        component_version=f.component_version,
        project_name=project_name,
        severity=f.severity,
        cvss_v3_base_score=f.cvss_v3_base_score,
        epss_score=f.epss_score,
        is_kev=ps.is_kev,
        priority_score=ps.value,
        priority_band=ps.band,
    )
