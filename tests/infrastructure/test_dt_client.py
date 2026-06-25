"""Tests del cliente HTTP de Dependency-Track (T-042)."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest
import respx

from vulntrack.infrastructure.dt.client import DtHttpClient

FIXTURES = Path(__file__).parent / "fixtures"
BASE_URL = "https://dt.example.com"
API_KEY = "test-api-key-123"


def make_client(semaphore: asyncio.Semaphore | None = None) -> DtHttpClient:
    return DtHttpClient(base_url=BASE_URL, api_key=API_KEY, semaphore=semaphore, timeout=5.0)


# ---------------------------------------------------------------------------
# get_server_version
# ---------------------------------------------------------------------------


class TestGetServerVersion:
    @respx.mock
    async def test_returns_version_string(self) -> None:
        respx.get(f"{BASE_URL}/api/v1/about").mock(
            return_value=httpx.Response(200, json={"version": "4.14.1", "application": "Dependency-Track"})
        )
        client = make_client()
        version = await client.get_server_version()
        assert version == "4.14.1"

    @respx.mock
    async def test_missing_version_returns_empty_string(self) -> None:
        respx.get(f"{BASE_URL}/api/v1/about").mock(
            return_value=httpx.Response(200, json={})
        )
        client = make_client()
        version = await client.get_server_version()
        assert version == ""


# ---------------------------------------------------------------------------
# get_projects / get_all_projects
# ---------------------------------------------------------------------------


class TestGetProjects:
    @respx.mock
    async def test_single_page(self) -> None:
        projects = [
            {"uuid": f"uuid-{i:04d}", "name": f"Project {i}"}
            for i in range(3)
        ]
        respx.get(f"{BASE_URL}/api/v1/project").mock(
            return_value=httpx.Response(
                200,
                json=projects,
                headers={"X-Total-Count": "3"},
            )
        )
        client = make_client()
        result, total = await client.get_projects()
        assert total == 3
        assert len(result) == 3
        assert result[0].uuid == "uuid-0000"

    @respx.mock
    async def test_pagination_three_pages(self) -> None:
        page1 = [{"uuid": f"uuid-{i:04d}", "name": f"P{i}"} for i in range(100)]
        page2 = [{"uuid": f"uuid-{i:04d}", "name": f"P{i}"} for i in range(100, 200)]
        page3 = [{"uuid": f"uuid-{i:04d}", "name": f"P{i}"} for i in range(200, 250)]

        call_count = 0

        def side_effect(request: httpx.Request, **kwargs: object) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(200, json=page1, headers={"X-Total-Count": "250"})
            elif call_count == 2:
                return httpx.Response(200, json=page2, headers={"X-Total-Count": "250"})
            else:
                return httpx.Response(200, json=page3, headers={"X-Total-Count": "250"})

        respx.get(f"{BASE_URL}/api/v1/project").mock(side_effect=side_effect)
        client = make_client()
        all_projects = await client.get_all_projects()
        assert len(all_projects) == 250
        assert call_count == 3

    @respx.mock
    async def test_empty_project_list(self) -> None:
        respx.get(f"{BASE_URL}/api/v1/project").mock(
            return_value=httpx.Response(200, json=[], headers={"X-Total-Count": "0"})
        )
        client = make_client()
        result, total = await client.get_projects()
        assert total == 0
        assert result == []


# ---------------------------------------------------------------------------
# get_project_metrics
# ---------------------------------------------------------------------------


class TestGetProjectMetrics:
    @respx.mock
    async def test_parse_metrics(self) -> None:
        raw = json.loads((FIXTURES / "dt_metrics.json").read_text())
        uuid = "proj-uuid-0001"
        respx.get(f"{BASE_URL}/api/v1/metrics/project/{uuid}/current").mock(
            return_value=httpx.Response(200, json=raw)
        )
        client = make_client()
        metrics = await client.get_project_metrics(uuid)
        assert metrics.critical == 3
        assert metrics.total == 49

    @respx.mock
    async def test_returns_zero_defaults_on_empty_body(self) -> None:
        uuid = "proj-uuid-0002"
        respx.get(f"{BASE_URL}/api/v1/metrics/project/{uuid}/current").mock(
            return_value=httpx.Response(200, json={})
        )
        client = make_client()
        metrics = await client.get_project_metrics(uuid)
        assert metrics.total == 0


# ---------------------------------------------------------------------------
# get_project_findings
# ---------------------------------------------------------------------------


class TestGetProjectFindings:
    @respx.mock
    async def test_parse_findings_fixture(self) -> None:
        raw = json.loads((FIXTURES / "dt_findings.json").read_text())
        uuid = "proj-uuid-0001"
        respx.get(f"{BASE_URL}/api/v1/finding/project/{uuid}").mock(
            return_value=httpx.Response(200, json=raw)
        )
        client = make_client()
        findings = await client.get_project_findings(uuid)
        assert len(findings) == 3
        assert findings[0].vulnerability.vuln_id == "CVE-2021-44228"

    @respx.mock
    async def test_suppressed_finding_included_in_response(self) -> None:
        raw = json.loads((FIXTURES / "dt_findings.json").read_text())
        uuid = "proj-uuid-0002"
        respx.get(f"{BASE_URL}/api/v1/finding/project/{uuid}").mock(
            return_value=httpx.Response(200, json=raw)
        )
        client = make_client()
        findings = await client.get_project_findings(uuid)
        suppressed = [f for f in findings if f.analysis and f.analysis.suppressed]
        assert len(suppressed) == 1


# ---------------------------------------------------------------------------
# get_project_metric_history
# ---------------------------------------------------------------------------


class TestGetProjectMetricHistory:
    @respx.mock
    async def test_parse_history_list(self) -> None:
        history = [
            {"critical": 2, "high": 5, "medium": 10, "low": 1, "unassigned": 0,
             "inheritedRiskScore": 4.5, "total": 18},
            {"critical": 1, "high": 3, "medium": 8, "low": 1, "unassigned": 0,
             "inheritedRiskScore": 3.0, "total": 13},
        ]
        uuid = "proj-uuid-0003"
        respx.get(f"{BASE_URL}/api/v1/metrics/project/{uuid}/days/90").mock(
            return_value=httpx.Response(200, json=history)
        )
        client = make_client()
        result = await client.get_project_metric_history(uuid)
        assert len(result) == 2
        assert result[0].critical == 2
        assert result[1].total == 13


# ---------------------------------------------------------------------------
# Reintentos y errores HTTP
# ---------------------------------------------------------------------------


class TestRetryBehavior:
    @respx.mock
    async def test_401_raises_immediately_no_retry(self) -> None:
        respx.get(f"{BASE_URL}/api/v1/about").mock(
            return_value=httpx.Response(401, json={"message": "Unauthorized"})
        )
        client = make_client()
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await client.get_server_version()
        assert exc_info.value.response.status_code == 401

    @respx.mock
    async def test_503_retries_three_times_then_raises(self) -> None:
        call_count = 0

        def fail_503(request: httpx.Request, **kwargs: object) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(503, json={"message": "Service Unavailable"})

        respx.get(f"{BASE_URL}/api/v1/about").mock(side_effect=fail_503)
        client = make_client()
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await client.get_server_version()
        assert exc_info.value.response.status_code == 503
        assert call_count == 3

    @respx.mock
    async def test_503_then_200_succeeds(self) -> None:
        call_count = 0

        def flaky(request: httpx.Request, **kwargs: object) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                return httpx.Response(503, json={"message": "Unavailable"})
            return httpx.Response(200, json={"version": "4.14.1"})

        respx.get(f"{BASE_URL}/api/v1/about").mock(side_effect=flaky)
        client = make_client()
        version = await client.get_server_version()
        assert version == "4.14.1"
        assert call_count == 2

    @respx.mock
    async def test_404_not_found_raises_without_retry(self) -> None:
        call_count = 0

        def not_found(request: httpx.Request, **kwargs: object) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(404, json={"message": "Not found"})

        respx.get(f"{BASE_URL}/api/v1/about").mock(side_effect=not_found)
        client = make_client()
        with pytest.raises(httpx.HTTPStatusError):
            await client.get_server_version()
        assert call_count == 1


# ---------------------------------------------------------------------------
# Semaphore / concurrencia
# ---------------------------------------------------------------------------


class TestSemaphore:
    @respx.mock
    async def test_semaphore_limits_concurrency(self) -> None:
        semaphore = asyncio.Semaphore(2)
        respx.get(f"{BASE_URL}/api/v1/about").mock(
            return_value=httpx.Response(200, json={"version": "4.14.1"})
        )
        client = make_client(semaphore=semaphore)
        tasks = [client.get_server_version() for _ in range(5)]
        results = await asyncio.gather(*tasks)
        assert all(v == "4.14.1" for v in results)

    @respx.mock
    async def test_x_api_key_header_sent(self) -> None:
        sent_headers: dict[str, str] = {}

        def capture(request: httpx.Request, **kwargs: object) -> httpx.Response:
            sent_headers.update(dict(request.headers))
            return httpx.Response(200, json={"version": "4.0.0"})

        respx.get(f"{BASE_URL}/api/v1/about").mock(side_effect=capture)
        client = make_client()
        await client.get_server_version()
        assert sent_headers.get("x-api-key") == API_KEY
