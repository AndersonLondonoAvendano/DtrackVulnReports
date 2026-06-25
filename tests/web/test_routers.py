"""Tests T-073 a T-079: routers de la interfaz web.

Usa TestClient de FastAPI con overrides de dependencias para no tocar DB real.
"""
from __future__ import annotations

from datetime import UTC, date, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from vulntrack.application.queries.dashboard_query import DashboardData, TaskSummary
from vulntrack.application.sync.sync_portfolio import SyncResult
from vulntrack.domain.value_objects.severity import Severity
from vulntrack.interfaces.web.main import create_app


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_dashboard_data(**kwargs: object) -> DashboardData:
    defaults: dict[str, object] = dict(
        total_vigentes=42,
        vigentes_por_severidad={
            Severity.CRITICAL: 5, Severity.HIGH: 10, Severity.MEDIUM: 20,
            Severity.LOW: 7, Severity.UNASSIGNED: 0,
        },
        proyectos_en_cero=2,
        proyectos_con_criticas=3,
        last_sync_at=datetime(2026, 6, 25, 10, 0, tzinfo=UTC),
        kev_hits_count=4,
        total_proyectos=8,
    )
    defaults.update(kwargs)
    return DashboardData(**defaults)  # type: ignore[arg-type]


# ── T-073: Sync ───────────────────────────────────────────────────────────────


class TestSyncRouter:
    def test_post_sync_run_returns_202(self) -> None:
        from vulntrack.interfaces.web.dependencies import get_sync_portfolio_use_case

        mock_uc = AsyncMock()
        mock_uc.execute.return_value = SyncResult(
            synced_projects=3, failed_projects=0, new_snapshots=3, duration_seconds=1.5
        )

        app = create_app()
        app.dependency_overrides[get_sync_portfolio_use_case] = lambda: mock_uc

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post("/api/v1/sync/run")
        assert resp.status_code == 202
        body = resp.json()
        assert body["status"] in ("started", "running")

    def test_get_sync_status_returns_idle_initially(self) -> None:
        app = create_app()
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/api/v1/sync/status")
        assert resp.status_code == 200
        body = resp.json()
        assert "status" in body
        assert "synced_projects" in body


# ── T-073: Dashboard ──────────────────────────────────────────────────────────


class TestDashboardRouter:
    def _app_with_dashboard(self) -> object:
        from vulntrack.interfaces.web.dependencies import get_dashboard_query

        data = _make_dashboard_data()
        mock_query = AsyncMock()
        mock_query.execute.return_value = data

        app = create_app()
        app.dependency_overrides[get_dashboard_query] = lambda: mock_query
        return app

    def test_get_dashboard_json_returns_kpis(self) -> None:
        app = self._app_with_dashboard()
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/api/v1/dashboard")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_vigentes"] == 42
        assert body["kev_hits_count"] == 4
        assert body["total_proyectos"] == 8
        assert "vigentes_por_severidad" in body

    def test_get_dashboard_html_returns_200(self) -> None:
        app = self._app_with_dashboard()
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "VulnTrack" in resp.text


# ── T-074: Proyectos ──────────────────────────────────────────────────────────


class TestProjectsRouter:
    def test_list_projects_returns_200(self) -> None:
        from vulntrack.interfaces.web.dependencies import get_project_repo
        from vulntrack.domain.entities.project import Project

        projects = [
            Project(uuid="u1", name="proj-alpha", version="1.0", description=None,
                    last_bom_import=None, last_synced_at=datetime.now(UTC)),
            Project(uuid="u2", name="proj-beta", version=None, description=None,
                    last_bom_import=None, last_synced_at=datetime.now(UTC)),
        ]
        mock_repo = AsyncMock()
        mock_repo.list_all.return_value = projects

        app = create_app()
        app.dependency_overrides[get_project_repo] = lambda: mock_repo

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/api/v1/projects")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2
        names = [p["name"] for p in body["items"]]
        assert "proj-alpha" in names

    def test_list_projects_search_filter(self) -> None:
        from vulntrack.interfaces.web.dependencies import get_project_repo
        from vulntrack.domain.entities.project import Project

        projects = [
            Project(uuid="u1", name="daviplata-frontend", version=None, description=None,
                    last_bom_import=None, last_synced_at=datetime.now(UTC)),
            Project(uuid="u2", name="core-banking", version=None, description=None,
                    last_bom_import=None, last_synced_at=datetime.now(UTC)),
        ]
        mock_repo = AsyncMock()
        mock_repo.list_all.return_value = projects

        app = create_app()
        app.dependency_overrides[get_project_repo] = lambda: mock_repo

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/api/v1/projects?search=daviplata")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["name"] == "daviplata-frontend"

    def test_get_project_not_found_returns_404(self) -> None:
        from vulntrack.interfaces.web.dependencies import get_project_detail_query
        from vulntrack.domain.exceptions import ProjectNotFoundError

        mock_query = AsyncMock()
        mock_query.execute.side_effect = ProjectNotFoundError("no-uuid")

        app = create_app()
        app.dependency_overrides[get_project_detail_query] = lambda: mock_query

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/api/v1/projects/no-uuid")
        assert resp.status_code == 404


# ── T-075: Reportes ───────────────────────────────────────────────────────────


class TestReportsRouter:
    def test_reports_html_returns_200(self) -> None:
        app = create_app()
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/reports")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_generate_report_xlsx(self) -> None:
        from vulntrack.interfaces.web.dependencies import get_generate_portfolio_use_case
        from vulntrack.application.reports.generate_portfolio_report import ReportFormat

        mock_uc = AsyncMock()
        mock_uc.execute.return_value = {ReportFormat.XLSX: b"PK\x03\x04fake-xlsx"}

        app = create_app()
        app.dependency_overrides[get_generate_portfolio_use_case] = lambda: mock_uc

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post("/api/v1/reports/generate", json={
                "period": "quarterly",
                "quarter": "Q2",
                "year": 2026,
                "formats": ["xlsx"],
            })
        assert resp.status_code == 200
        assert "Content-Disposition" in resp.headers
        assert "Reporte_Portafolio" in resp.headers["Content-Disposition"]
        assert resp.content == b"PK\x03\x04fake-xlsx"

    def test_generate_report_invalid_period_returns_422(self) -> None:
        app = create_app()
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post("/api/v1/reports/generate", json={
                "period": "quarterly",
                "year": None,  # year missing for quarterly
                "formats": ["xlsx"],
            })
        assert resp.status_code == 422


# ── T-076: Priorización ───────────────────────────────────────────────────────


class TestPrioritizationRouter:
    def test_get_prioritized_findings_returns_list(self) -> None:
        from vulntrack.interfaces.web.dependencies import get_prioritized_findings_query
        from vulntrack.domain.entities.finding import Finding
        from vulntrack.domain.value_objects.priority_score import PriorityBand, PriorityScore

        mock_query = AsyncMock()

        class _Item:
            pass

        item = _Item()
        f = Finding(
            id=1, project_uuid="u1", dt_finding_uuid="dt-1",
            component_name="log4j", component_version="2.14.0", component_group=None,
            vuln_id="CVE-2021-44228", vuln_source="NVD", severity=Severity.CRITICAL,
            cvss_v3_base_score=10.0, epss_score=0.975, epss_percentile=None,
            attributed_on=None, suppressed=False, last_synced_at=datetime.now(UTC),
        )
        item.finding = f  # type: ignore[attr-defined]
        item.score = PriorityScore(value=95.0, band=PriorityBand.IMMEDIATE, is_kev=True, breakdown={})  # type: ignore[attr-defined]
        mock_query.execute.return_value = [item]

        app = create_app()
        app.dependency_overrides[get_prioritized_findings_query] = lambda: mock_query

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/api/v1/findings/prioritized")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        assert body[0]["vuln_id"] == "CVE-2021-44228"
        assert body[0]["is_kev"] is True

    def test_kev_only_filter_forwarded(self) -> None:
        from vulntrack.interfaces.web.dependencies import get_prioritized_findings_query

        mock_query = AsyncMock()
        mock_query.execute.return_value = []

        app = create_app()
        app.dependency_overrides[get_prioritized_findings_query] = lambda: mock_query

        with TestClient(app, raise_server_exceptions=False) as client:
            client.get("/api/v1/findings/prioritized?kev_only=true")
        mock_query.execute.assert_called_once_with(kev_only=True, min_cvss=None, min_epss=None)

    def test_get_thresholds_returns_bands(self) -> None:
        app = create_app()
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/api/v1/findings/thresholds")
        assert resp.status_code == 200
        body = resp.json()
        assert "bands" in body
        assert "IMMEDIATE" in body["bands"]


# ── T-077: KEV ───────────────────────────────────────────────────────────────


class TestKevRouter:
    def test_kev_refresh_returns_202(self) -> None:
        from vulntrack.interfaces.web.dependencies import get_sync_kev_use_case

        mock_uc = AsyncMock()
        app = create_app()
        app.dependency_overrides[get_sync_kev_use_case] = lambda: mock_uc

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post("/api/v1/kev/refresh")
        assert resp.status_code == 202
        assert resp.json()["status"] in ("started", "running")

    def test_kev_status_no_catalog(self) -> None:
        from vulntrack.interfaces.web.dependencies import get_kev_repo

        mock_repo = AsyncMock()
        mock_repo.get_catalog_meta.return_value = None

        app = create_app()
        app.dependency_overrides[get_kev_repo] = lambda: mock_repo

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/api/v1/kev/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["is_stale"] is True
        assert body["entries_count"] == 0


# ── T-078: Remediación ────────────────────────────────────────────────────────


class TestRemediationRouter:
    def test_suggest_tasks_returns_list(self) -> None:
        from vulntrack.interfaces.web.dependencies import get_suggest_tasks_use_case
        from vulntrack.domain.entities.remediation import RemediationTask, TaskStatus
        from vulntrack.domain.value_objects.priority_score import PriorityBand

        now = datetime.now(UTC)
        task = RemediationTask(
            id=1, plan_id=1, finding_id=1, title="Fix CVE-KEV",
            description=None, assignee=None, status=TaskStatus.PENDING,
            priority_band=PriorityBand.IMMEDIATE,
            recommended_action="Explotación activa confirmada",
            target_date=date(2026, 7, 2), completed_at=None, notes=None,
            created_at=now, updated_at=now,
        )
        mock_uc = AsyncMock()
        mock_uc.execute.return_value = [task]

        app = create_app()
        app.dependency_overrides[get_suggest_tasks_use_case] = lambda: mock_uc

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post("/api/v1/remediation/plans/1/suggest")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        assert body[0]["priority_band"] == "IMMEDIATE"

    def test_export_plan_xlsx(self) -> None:
        from vulntrack.interfaces.web.dependencies import get_export_plan_use_case

        mock_uc = AsyncMock()
        mock_uc.execute.return_value = b"PK\x03\x04fake-xlsx"

        app = create_app()
        app.dependency_overrides[get_export_plan_use_case] = lambda: mock_uc

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post("/api/v1/remediation/plans/1/export?fmt=xlsx")
        assert resp.status_code == 200
        assert resp.content == b"PK\x03\x04fake-xlsx"


# ── T-079: Configuración ──────────────────────────────────────────────────────


class TestConfigRouter:
    def _mock_app_settings_repo(self) -> object:
        from vulntrack.infrastructure.persistence.repositories.app_settings_repo import AppSettings

        cfg = AppSettings(
            id=1, sync_interval_hours=6, kev_stale_days=7,
            last_sync_at=None, last_kev_update_at=None,
            w_cvss_weight=0.30, w_epss_weight=0.40, w_kev_weight=0.30,
            kev_minimum_score=75.0, epss_high_threshold=0.40, cvss_high_threshold=7.0,
            updated_at=datetime.now(UTC),
        )
        mock_repo = AsyncMock()
        mock_repo.get.return_value = cfg
        return mock_repo

    def test_get_config_returns_200(self) -> None:
        from vulntrack.interfaces.web.dependencies import get_app_settings_repo

        mock_repo = self._mock_app_settings_repo()
        app = create_app()
        app.dependency_overrides[get_app_settings_repo] = lambda: mock_repo

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/api/v1/config")
        assert resp.status_code == 200
        body = resp.json()
        assert body["sync_interval_hours"] == 6
        assert body["w_cvss_weight"] == pytest.approx(0.30)

    def test_test_connection_dt_error(self) -> None:
        from vulntrack.interfaces.web.dependencies import get_dt_client

        mock_client = AsyncMock()
        mock_client.get_server_version.side_effect = Exception("connection refused")

        app = create_app()
        app.dependency_overrides[get_dt_client] = lambda: mock_client

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post("/api/v1/config/test-connection")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is False
        assert "connection refused" in body["error"]

    def test_test_connection_success(self) -> None:
        from vulntrack.interfaces.web.dependencies import get_dt_client

        mock_client = AsyncMock()
        mock_client.get_server_version.return_value = "4.14.1"

        app = create_app()
        app.dependency_overrides[get_dt_client] = lambda: mock_client

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post("/api/v1/config/test-connection")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["dt_version"] == "4.14.1"
