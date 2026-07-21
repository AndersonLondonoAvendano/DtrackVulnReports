"""T-061: Caso de uso SyncPortfolio — sincroniza proyectos y hallazgos desde DT."""
from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import TYPE_CHECKING

from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.metric_snapshot import MetricSnapshot, SnapshotSource
from vulntrack.domain.entities.project import Project
from vulntrack.domain.ports.app_settings_repository import AppSettingsRepository
from vulntrack.domain.ports.dt_client import DtClientPort
from vulntrack.domain.ports.finding_repository import FindingRepository
from vulntrack.domain.ports.project_repository import ProjectRepository
from vulntrack.domain.ports.snapshot_repository import SnapshotRepository
from vulntrack.domain.services.cve_normalizer import extract_cve
from vulntrack.domain.services.cvss_parser import parse_cvss_v3_base_score
from vulntrack.domain.value_objects.severity import Severity
from vulntrack.infrastructure.dt.response_models import (
    DtFinding,
    DtMetrics,
    DtMetricsHistory,
    DtProject,
)

if TYPE_CHECKING:
    from vulntrack.application.sync.finding_reconciler import FindingReconciler
    from vulntrack.application.sync.treatment_sync_reconciler import TreatmentSyncReconciler

logger = logging.getLogger(__name__)

_BACKFILL_DAYS = 90


@dataclass
class SyncResult:
    synced_projects: int = 0
    failed_projects: int = 0
    new_snapshots: int = 0
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)


class SyncPortfolioUseCase:
    def __init__(
        self,
        dt_client: DtClientPort,
        project_repo: ProjectRepository,
        finding_repo: FindingRepository,
        snapshot_repo: SnapshotRepository,
        app_settings_repo: AppSettingsRepository | None = None,
        treatment_reconciler: TreatmentSyncReconciler | None = None,
        finding_reconciler: FindingReconciler | None = None,
    ) -> None:
        self._dt = dt_client
        self._project_repo = project_repo
        self._finding_repo = finding_repo
        self._snapshot_repo = snapshot_repo
        self._app_settings_repo = app_settings_repo
        self._treatment_reconciler = treatment_reconciler
        self._finding_reconciler = finding_reconciler

    async def execute(self) -> SyncResult:
        result = SyncResult()
        started_at = datetime.now(UTC)

        # 1. Fetch all projects from DT
        try:
            raw_projects: list[object] = await self._dt.get_all_projects()
        except Exception as exc:
            logger.error("sync_portfolio_fetch_projects_failed error=%s", exc)
            result.errors.append(f"fetch_projects: {exc}")
            result.duration_seconds = (datetime.now(UTC) - started_at).total_seconds()
            return result

        dt_projects = [DtProject.model_validate(p) for p in raw_projects]

        # Check if backfill is needed (first sync)
        historical_count = await self._snapshot_repo.count_by_source(
            SnapshotSource.DT_HISTORICAL.value
        )
        needs_backfill = historical_count == 0

        # 2 & 3. Sync each project (metrics + findings) with bounded concurrency
        sem = asyncio.Semaphore(5)

        async def sync_one(dt_proj: DtProject) -> None:
            async with sem:
                try:
                    await self._sync_project(
                        dt_proj, result, needs_backfill=needs_backfill
                    )
                    result.synced_projects += 1
                    logger.info("sync_project_ok project=%s", dt_proj.name)
                except Exception as exc:
                    result.failed_projects += 1
                    result.errors.append(f"{dt_proj.name}: {exc}")
                    logger.error(
                        "sync_project_failed project=%s error=%s", dt_proj.name, exc
                    )

        await asyncio.gather(*[sync_one(p) for p in dt_projects])
        result.duration_seconds = (datetime.now(UTC) - started_at).total_seconds()

        if self._app_settings_repo is not None:
            try:
                await self._app_settings_repo.update(last_sync_at=started_at)
            except Exception as exc:
                logger.warning("sync_last_sync_at_update_failed error=%s", exc)

        logger.info(
            "sync_portfolio_done synced=%d failed=%d duration=%.1fs",
            result.synced_projects,
            result.failed_projects,
            result.duration_seconds,
        )
        return result

    async def _sync_project(
        self, dt_proj: DtProject, result: SyncResult, *, needs_backfill: bool
    ) -> None:
        now = datetime.now(UTC)

        # Upsert project entity
        project = Project(
            uuid=dt_proj.uuid,
            name=dt_proj.name,
            version=dt_proj.version,
            description=dt_proj.description,
            last_bom_import=dt_proj.last_bom_import,
            last_synced_at=now,
        )
        await self._project_repo.upsert(project)

        # Fetch current metrics → snapshot for today
        raw_metrics: object = await self._dt.get_project_metrics(dt_proj.uuid)
        metrics = DtMetrics.model_validate(raw_metrics)
        today = date.today()
        snapshot = _metrics_to_snapshot(dt_proj.uuid, metrics, today, SnapshotSource.DT_CURRENT)
        await self._snapshot_repo.upsert(snapshot)
        result.new_snapshots += 1

        # Backfill: only on first sync
        if needs_backfill:
            raw_history: list[object] = await self._dt.get_project_metric_history(
                dt_proj.uuid, days=_BACKFILL_DAYS
            )
            for raw_hist in raw_history:
                hist = DtMetricsHistory.model_validate(raw_hist)
                hist_date = _extract_date(hist)
                if hist_date is not None and hist_date != today:
                    hist_snap = _metrics_history_to_snapshot(
                        dt_proj.uuid, hist, hist_date
                    )
                    await self._snapshot_repo.upsert(hist_snap)
                    result.new_snapshots += 1

        # Fetch and upsert findings — fallo tolerado: proyecto y métricas ya persistidos
        try:
            raw_findings: list[object] = await self._dt.get_project_findings(dt_proj.uuid)
            findings = [
                _dt_finding_to_domain(dt_proj.uuid, f, now)
                for f in [DtFinding.model_validate(rf) for rf in raw_findings]
            ]
            if not findings and metrics.critical + metrics.high + metrics.medium + metrics.low > 0:
                logger.warning(
                    "sync_findings_empty_but_metrics_nonzero project=%s "
                    "critical=%d high=%d medium=%d low=%d",
                    dt_proj.name,
                    metrics.critical,
                    metrics.high,
                    metrics.medium,
                    metrics.low,
                )

            # Bloque B (T-E013/T-E014): reconcilia identidad D1 -- NUEVA/
            # SE_MANTIENE/DESAPARECIÓ(→RESUELTA)/REAPARECIÓ(→reincidente). Si no
            # hay `finding_reconciler` configurado, se conserva el upsert directo
            # (compatibilidad hacia atrás).
            reconciliation_summary = None
            if self._finding_reconciler is not None:
                reconciliation_summary = await self._finding_reconciler.reconcile(
                    dt_proj.uuid, findings, now
                )
            elif findings:
                await self._finding_repo.upsert_batch(findings)

            # D3: auto-finaliza tratamientos cuya vulnerabilidad desapareció y
            # reabre los que reaparecieron (mismo id, T-D023). Sólo se ejecuta
            # si el fetch de findings tuvo éxito (no en el except de abajo) y
            # hay un resumen de reconciliación con el que trabajar.
            if self._treatment_reconciler is not None and reconciliation_summary is not None:
                await self._treatment_reconciler.reconcile_from_summary(
                    dt_proj.uuid, reconciliation_summary, synced_at=now
                )
        except Exception as findings_exc:
            import httpx as _httpx
            if isinstance(findings_exc, _httpx.HTTPStatusError):
                logger.warning(
                    "sync_findings_http_error project=%s status=%d url=%s",
                    dt_proj.name,
                    findings_exc.response.status_code,
                    str(findings_exc.request.url),
                )
            else:
                logger.warning(
                    "sync_findings_failed project=%s error_type=%s error=%s",
                    dt_proj.name,
                    type(findings_exc).__name__,
                    findings_exc,
                )


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _metrics_to_snapshot(
    project_uuid: str,
    m: DtMetrics,
    snap_date: date,
    source: SnapshotSource,
) -> MetricSnapshot:
    return MetricSnapshot(
        id=0,
        project_uuid=project_uuid,
        snapshot_date=snap_date,
        critical=m.critical,
        high=m.high,
        medium=m.medium,
        low=m.low,
        unassigned=m.unassigned,
        total=m.total,
        risk_score=m.risk_score,
        source=source,
    )


def _metrics_history_to_snapshot(
    project_uuid: str,
    h: DtMetricsHistory,
    snap_date: date,
) -> MetricSnapshot:
    return MetricSnapshot(
        id=0,
        project_uuid=project_uuid,
        snapshot_date=snap_date,
        critical=h.critical,
        high=h.high,
        medium=h.medium,
        low=h.low,
        unassigned=h.unassigned,
        total=h.total,
        risk_score=h.risk_score,
        source=SnapshotSource.DT_HISTORICAL,
    )


def _extract_date(hist: DtMetricsHistory) -> date | None:
    ts = hist.last_occurrence or hist.first_occurrence
    if ts is None:
        return None
    return ts.date()


_SEV_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _dt_finding_to_domain(
    project_uuid: str, f: DtFinding, synced_at: datetime
) -> Finding:
    sev_str = f.vulnerability.severity.upper()
    sev = _SEV_MAP.get(sev_str, Severity.UNASSIGNED)
    attributed_on = f.attribution.attributed_on if f.attribution else None
    if f.attribution and f.attribution.finding_uuid:
        finding_uuid = f.attribution.finding_uuid
    else:
        # Genera UUID5 determinista e incluye project_uuid para evitar colisiones
        # entre proyectos que comparten el mismo componente en DT.
        key = f"{project_uuid}:{f.component.uuid or ''}:{f.vulnerability.vuln_id}"
        finding_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, key))
    suppressed = f.analysis.suppressed if f.analysis else False

    # CVE canónico extraído de aliases (GHSA→CVE); None si no hay CVE.
    cve_id = extract_cve(
        vuln_id=f.vulnerability.vuln_id,
        source=f.vulnerability.source,
        aliases=f.vulnerability.aliases,
    )

    # CVSS: producción devuelve cvssV3BaseScore directamente.
    # Instancias sin ese campo (v4.14 pruebas) usan el vector como fallback.
    cvss_score = f.vulnerability.cvss_v3_base_score
    if cvss_score is None and f.vulnerability.cvss_v3_vector:
        cvss_score = parse_cvss_v3_base_score(f.vulnerability.cvss_v3_vector)

    return Finding(
        id=0,
        project_uuid=project_uuid,
        dt_finding_uuid=finding_uuid or "",
        component_name=f.component.name,
        component_version=f.component.version,
        component_group=f.component.group,
        vuln_id=f.vulnerability.vuln_id,
        vuln_source=f.vulnerability.source,
        severity=sev,
        cve_id=cve_id,
        cvss_v3_base_score=cvss_score,
        epss_score=f.vulnerability.epss_score,
        epss_percentile=f.vulnerability.epss_percentile,
        attributed_on=attributed_on,
        suppressed=suppressed,
        last_synced_at=synced_at,
    )
