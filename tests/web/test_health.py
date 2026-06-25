"""Tests del healthcheck y arranque de la app."""
from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_returns_ok() -> None:
    from vulntrack.interfaces.web.main import create_app

    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/health")
    assert response.status_code in (200, 503)
    data = response.json()
    assert "status" in data
    assert "db" in data
    assert "dt_reachable" in data
    assert isinstance(data["dt_reachable"], bool)
    assert "app_version" in data


def test_root_returns_html() -> None:
    from unittest.mock import AsyncMock
    from vulntrack.interfaces.web.main import create_app
    from vulntrack.interfaces.web.dependencies import get_dashboard_query
    from vulntrack.application.queries.dashboard_query import DashboardData, TaskSummary
    from vulntrack.domain.value_objects.severity import Severity

    data = DashboardData(
        total_vigentes=0,
        vigentes_por_severidad={s: 0 for s in Severity},
        proyectos_en_cero=0,
        proyectos_con_criticas=0,
        last_sync_at=None,
        kev_hits_count=0,
        total_proyectos=0,
    )
    mock_query = AsyncMock()
    mock_query.execute.return_value = data

    app = create_app()
    app.dependency_overrides[get_dashboard_query] = lambda: mock_query

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/")
    assert response.status_code == 200
    assert "VulnTrack" in response.text
