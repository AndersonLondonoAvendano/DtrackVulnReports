"""Contenedor de dependencias FastAPI — T-071.

Cada función es una dependency inyectable con Depends().
Las dependencias de repositorios son por-request (usan la sesión DB del request).
Las dependencias de clientes externos se crean por-request pero son stateless.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from vulntrack.application.queries.available_vulnerabilities_query import (
    ListAvailableVulnerabilitiesQuery,
)
from vulntrack.application.queries.dashboard_query import DashboardQuery
from vulntrack.application.queries.prioritized_findings_query import PrioritizedFindingsQuery
from vulntrack.application.queries.project_detail_query import ProjectDetailQuery
from vulntrack.application.queries.quarterly_metrics_query import QuarterlyMetricsQuery
from vulntrack.application.remediation.create_plan import CreatePlanUseCase
from vulntrack.application.remediation.export_plan import ExportPlanUseCase
from vulntrack.application.reports.build_report_data import BuildReportDataUseCase
from vulntrack.application.reports.generate_portfolio_report import (
    GeneratePortfolioReportUseCase,
    ReportFormat,
)
from vulntrack.application.reports.generate_project_report import GenerateProjectReportUseCase
from vulntrack.application.sprints.close_sprint import CloseSprintUseCase
from vulntrack.application.sprints.create_sprint import CreateSprintUseCase
from vulntrack.application.sprints.update_sprint import UpdateSprintUseCase
from vulntrack.application.sync.finding_reconciler import FindingReconciler
from vulntrack.application.sync.sync_kev import SyncKevUseCase
from vulntrack.application.sync.sync_portfolio import SyncPortfolioUseCase
from vulntrack.application.sync.treatment_sync_reconciler import TreatmentSyncReconciler
from vulntrack.application.treatments.create_treatments import CreateTreatmentsUseCase
from vulntrack.application.treatments.generate_top_score_treatments import (
    GenerateTreatmentsFromTopScoreUseCase,
)
from vulntrack.application.treatments.update_treatment import UpdateTreatmentUseCase
from vulntrack.config import Settings, get_settings
from vulntrack.domain.services.kev_matcher import KevMatcher
from vulntrack.infrastructure.dt.client import DtHttpClient
from vulntrack.infrastructure.kev.cisa_kev_client import CisaKevClient
from vulntrack.infrastructure.persistence.database import get_session
from vulntrack.infrastructure.persistence.repositories.app_settings_repo import (
    SqliteAppSettingsRepository,
)
from vulntrack.infrastructure.persistence.repositories.finding_repo import SqliteFindingRepository
from vulntrack.infrastructure.persistence.repositories.kev_repo import SqliteKevRepository
from vulntrack.infrastructure.persistence.repositories.project_repo import SqliteProjectRepository
from vulntrack.infrastructure.persistence.repositories.remediation_repo import (
    SqliteRemediationRepository,
)
from vulntrack.infrastructure.persistence.repositories.snapshot_repo import (
    SqliteSnapshotRepository,
)
from vulntrack.infrastructure.persistence.repositories.sprint_repo import SqliteSprintRepository
from vulntrack.infrastructure.persistence.repositories.treatment_repo import (
    SqliteTreatmentRepository,
)
# NOTE: DocxGenerator, XlsxGenerator, PdfGenerator imported lazily in _make_generators()
# to avoid WeasyPrint/GTK import errors on Windows where GTK is unavailable.

# ── Sesión DB ─────────────────────────────────────────────────────────────────


async def get_db(
    session: AsyncSession = Depends(get_session),  # noqa: B008
) -> AsyncGenerator[AsyncSession, None]:
    yield session  # type: ignore[misc]


def get_app_settings() -> Settings:
    return get_settings()


# ── Repositorios (por-request, comparten sesión) ──────────────────────────────


async def get_project_repo(
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> SqliteProjectRepository:
    return SqliteProjectRepository(db)


async def get_finding_repo(
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> SqliteFindingRepository:
    return SqliteFindingRepository(db)


async def get_snapshot_repo(
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> SqliteSnapshotRepository:
    return SqliteSnapshotRepository(db)


async def get_kev_repo(
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> SqliteKevRepository:
    return SqliteKevRepository(db)


async def get_remediation_repo(
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> SqliteRemediationRepository:
    return SqliteRemediationRepository(db)


async def get_app_settings_repo(
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> SqliteAppSettingsRepository:
    return SqliteAppSettingsRepository(db)


async def get_sprint_repo(
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> SqliteSprintRepository:
    return SqliteSprintRepository(db)


async def get_treatment_repo(
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> SqliteTreatmentRepository:
    return SqliteTreatmentRepository(db)


# ── Clientes externos ─────────────────────────────────────────────────────────


def get_dt_client(
    settings: Settings = Depends(get_app_settings),  # noqa: B008
) -> DtHttpClient:
    return DtHttpClient(
        base_url=settings.dt_base_url_str,
        api_key=settings.dt_api_key,
        semaphore=asyncio.Semaphore(5),
    )


def get_kev_client() -> CisaKevClient:
    return CisaKevClient()


# ── KevMatcher (cargado desde BD por-request) ─────────────────────────────────


async def get_kev_matcher(
    kev_repo: SqliteKevRepository = Depends(get_kev_repo),  # noqa: B008
) -> KevMatcher:
    entries = await kev_repo.list_all()
    return KevMatcher(entries)


# ── Queries ───────────────────────────────────────────────────────────────────


async def get_dashboard_query(
    project_repo: SqliteProjectRepository = Depends(get_project_repo),  # noqa: B008
    finding_repo: SqliteFindingRepository = Depends(get_finding_repo),  # noqa: B008
    kev_repo: SqliteKevRepository = Depends(get_kev_repo),  # noqa: B008
    treatment_repo: SqliteTreatmentRepository = Depends(get_treatment_repo),  # noqa: B008
    app_settings_repo: SqliteAppSettingsRepository = Depends(get_app_settings_repo),  # noqa: B008
) -> DashboardQuery:
    app_cfg = await app_settings_repo.get()
    return DashboardQuery(
        project_repo=project_repo,
        finding_repo=finding_repo,
        kev_repo=kev_repo,
        treatment_repo=treatment_repo,
        last_sync_at=app_cfg.last_sync_at,
    )


async def get_project_detail_query(
    project_repo: SqliteProjectRepository = Depends(get_project_repo),  # noqa: B008
    finding_repo: SqliteFindingRepository = Depends(get_finding_repo),  # noqa: B008
    snapshot_repo: SqliteSnapshotRepository = Depends(get_snapshot_repo),  # noqa: B008
    remediation_repo: SqliteRemediationRepository = Depends(get_remediation_repo),  # noqa: B008
    treatment_repo: SqliteTreatmentRepository = Depends(get_treatment_repo),  # noqa: B008
    kev_matcher: KevMatcher = Depends(get_kev_matcher),  # noqa: B008
) -> ProjectDetailQuery:
    return ProjectDetailQuery(
        project_repo=project_repo,
        finding_repo=finding_repo,
        snapshot_repo=snapshot_repo,
        remediation_repo=remediation_repo,
        treatment_repo=treatment_repo,
        kev_matcher=kev_matcher,
    )


async def get_prioritized_findings_query(
    finding_repo: SqliteFindingRepository = Depends(get_finding_repo),  # noqa: B008
    kev_matcher: KevMatcher = Depends(get_kev_matcher),  # noqa: B008
    project_repo: SqliteProjectRepository = Depends(get_project_repo),  # noqa: B008
    treatment_repo: SqliteTreatmentRepository = Depends(get_treatment_repo),  # noqa: B008
    sprint_repo: SqliteSprintRepository = Depends(get_sprint_repo),  # noqa: B008
) -> PrioritizedFindingsQuery:
    return PrioritizedFindingsQuery(
        finding_repo=finding_repo,
        kev_matcher=kev_matcher,
        project_repo=project_repo,
        treatment_repo=treatment_repo,
        sprint_repo=sprint_repo,
    )


async def get_available_vulnerabilities_query(
    treatment_repo: SqliteTreatmentRepository = Depends(get_treatment_repo),  # noqa: B008
    kev_matcher: KevMatcher = Depends(get_kev_matcher),  # noqa: B008
) -> ListAvailableVulnerabilitiesQuery:
    return ListAvailableVulnerabilitiesQuery(
        treatment_repo=treatment_repo, kev_matcher=kev_matcher
    )


async def get_quarterly_metrics_query(
    treatment_repo: SqliteTreatmentRepository = Depends(get_treatment_repo),  # noqa: B008
    sprint_repo: SqliteSprintRepository = Depends(get_sprint_repo),  # noqa: B008
    finding_repo: SqliteFindingRepository = Depends(get_finding_repo),  # noqa: B008
) -> QuarterlyMetricsQuery:
    return QuarterlyMetricsQuery(
        treatment_repo=treatment_repo, sprint_repo=sprint_repo, finding_repo=finding_repo
    )


# ── Sync use cases ────────────────────────────────────────────────────────────


async def get_treatment_sync_reconciler(
    treatment_repo: SqliteTreatmentRepository = Depends(get_treatment_repo),  # noqa: B008
) -> TreatmentSyncReconciler:
    return TreatmentSyncReconciler(treatment_repo=treatment_repo)


async def get_finding_reconciler(
    finding_repo: SqliteFindingRepository = Depends(get_finding_repo),  # noqa: B008
) -> FindingReconciler:
    return FindingReconciler(finding_repo=finding_repo)


async def get_sync_portfolio_use_case(
    dt_client: DtHttpClient = Depends(get_dt_client),  # noqa: B008
    project_repo: SqliteProjectRepository = Depends(get_project_repo),  # noqa: B008
    finding_repo: SqliteFindingRepository = Depends(get_finding_repo),  # noqa: B008
    snapshot_repo: SqliteSnapshotRepository = Depends(get_snapshot_repo),  # noqa: B008
    treatment_reconciler: TreatmentSyncReconciler = Depends(  # noqa: B008
        get_treatment_sync_reconciler
    ),
    finding_reconciler: FindingReconciler = Depends(get_finding_reconciler),  # noqa: B008
) -> SyncPortfolioUseCase:
    return SyncPortfolioUseCase(
        dt_client=dt_client,
        project_repo=project_repo,
        finding_repo=finding_repo,
        snapshot_repo=snapshot_repo,
        treatment_reconciler=treatment_reconciler,
        finding_reconciler=finding_reconciler,
    )


async def get_sync_kev_use_case(
    kev_client: CisaKevClient = Depends(get_kev_client),  # noqa: B008
    kev_repo: SqliteKevRepository = Depends(get_kev_repo),  # noqa: B008
) -> SyncKevUseCase:
    return SyncKevUseCase(kev_client=kev_client, kev_repo=kev_repo)


# ── Report use cases ──────────────────────────────────────────────────────────


def _make_generators() -> dict[ReportFormat, object]:
    from vulntrack.infrastructure.reports.docx_generator import DocxGenerator
    from vulntrack.infrastructure.reports.xlsx_generator import XlsxGenerator

    generators: dict[ReportFormat, object] = {
        ReportFormat.DOCX: DocxGenerator(),
        ReportFormat.XLSX: XlsxGenerator(),
    }
    try:
        from vulntrack.infrastructure.reports.pdf_generator import PdfGenerator
        generators[ReportFormat.PDF] = PdfGenerator()
    except OSError:
        pass  # WeasyPrint/GTK unavailable on this platform
    return generators


def is_pdf_generation_available() -> bool:
    """Usado por la pantalla de reportes para deshabilitar la opción PDF en
    vez de dejar que el usuario la elija y falle recién al generar."""
    try:
        from vulntrack.infrastructure.reports.pdf_generator import PdfGenerator

        PdfGenerator()
        return True
    except OSError:
        return False


async def get_build_report_use_case(
    project_repo: SqliteProjectRepository = Depends(get_project_repo),  # noqa: B008
    finding_repo: SqliteFindingRepository = Depends(get_finding_repo),  # noqa: B008
    snapshot_repo: SqliteSnapshotRepository = Depends(get_snapshot_repo),  # noqa: B008
    kev_repo: SqliteKevRepository = Depends(get_kev_repo),  # noqa: B008
    treatment_repo: SqliteTreatmentRepository = Depends(get_treatment_repo),  # noqa: B008
    sprint_repo: SqliteSprintRepository = Depends(get_sprint_repo),  # noqa: B008
) -> BuildReportDataUseCase:
    return BuildReportDataUseCase(
        project_repo=project_repo,
        finding_repo=finding_repo,
        snapshot_repo=snapshot_repo,
        kev_repo=kev_repo,
        treatment_repo=treatment_repo,
        sprint_repo=sprint_repo,
    )


async def get_generate_portfolio_use_case(
    build_uc: BuildReportDataUseCase = Depends(get_build_report_use_case),  # noqa: B008
) -> GeneratePortfolioReportUseCase:
    from vulntrack.domain.ports.report_generator import ReportGenerator  # type: ignore[attr-defined]
    generators: dict[ReportFormat, ReportGenerator] = _make_generators()  # type: ignore[assignment]
    return GeneratePortfolioReportUseCase(build_use_case=build_uc, generators=generators)


async def get_generate_project_use_case(
    build_uc: BuildReportDataUseCase = Depends(get_build_report_use_case),  # noqa: B008
) -> GenerateProjectReportUseCase:
    from vulntrack.domain.ports.report_generator import ReportGenerator  # type: ignore[attr-defined]
    generators: dict[ReportFormat, ReportGenerator] = _make_generators()  # type: ignore[assignment]
    return GenerateProjectReportUseCase(build_use_case=build_uc, generators=generators)


# ── Remediation use cases ─────────────────────────────────────────────────────


async def get_create_plan_use_case(
    repo: SqliteRemediationRepository = Depends(get_remediation_repo),  # noqa: B008
    sprint_repo: SqliteSprintRepository = Depends(get_sprint_repo),  # noqa: B008
) -> CreatePlanUseCase:
    return CreatePlanUseCase(repo=repo, sprint_repo=sprint_repo)


async def get_export_plan_use_case(
    repo: SqliteRemediationRepository = Depends(get_remediation_repo),  # noqa: B008
    treatment_repo: SqliteTreatmentRepository = Depends(get_treatment_repo),  # noqa: B008
) -> ExportPlanUseCase:
    return ExportPlanUseCase(repo=repo, treatment_repo=treatment_repo)


# ── Sprint use cases ──────────────────────────────────────────────────────────


async def get_create_sprint_use_case(
    repo: SqliteSprintRepository = Depends(get_sprint_repo),  # noqa: B008
) -> CreateSprintUseCase:
    return CreateSprintUseCase(repo=repo)


async def get_close_sprint_use_case(
    sprint_repo: SqliteSprintRepository = Depends(get_sprint_repo),  # noqa: B008
    treatment_repo: SqliteTreatmentRepository = Depends(get_treatment_repo),  # noqa: B008
) -> CloseSprintUseCase:
    return CloseSprintUseCase(sprint_repo=sprint_repo, treatment_repo=treatment_repo)


async def get_update_sprint_use_case(
    repo: SqliteSprintRepository = Depends(get_sprint_repo),  # noqa: B008
) -> UpdateSprintUseCase:
    return UpdateSprintUseCase(repo=repo)


# ── Treatment use cases ───────────────────────────────────────────────────────


async def get_create_treatments_use_case(
    treatment_repo: SqliteTreatmentRepository = Depends(get_treatment_repo),  # noqa: B008
    finding_repo: SqliteFindingRepository = Depends(get_finding_repo),  # noqa: B008
    kev_matcher: KevMatcher = Depends(get_kev_matcher),  # noqa: B008
) -> CreateTreatmentsUseCase:
    return CreateTreatmentsUseCase(
        treatment_repo=treatment_repo, finding_repo=finding_repo, kev_matcher=kev_matcher
    )


async def get_update_treatment_use_case(
    repo: SqliteTreatmentRepository = Depends(get_treatment_repo),  # noqa: B008
) -> UpdateTreatmentUseCase:
    return UpdateTreatmentUseCase(repo=repo)


async def get_generate_top_score_treatments_use_case(
    available_query: ListAvailableVulnerabilitiesQuery = Depends(  # noqa: B008
        get_available_vulnerabilities_query
    ),
    create_treatments_uc: CreateTreatmentsUseCase = Depends(  # noqa: B008
        get_create_treatments_use_case
    ),
) -> GenerateTreatmentsFromTopScoreUseCase:
    return GenerateTreatmentsFromTopScoreUseCase(
        available_query=available_query, create_treatments_uc=create_treatments_uc
    )
