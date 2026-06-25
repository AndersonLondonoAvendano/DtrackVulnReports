"""Cliente HTTP para la API REST de Dependency-Track v4.x."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx
from tenacity import (
    AsyncRetrying,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from vulntrack.infrastructure.dt.response_models import (
    DtAbout,
    DtFinding,
    DtMetrics,
    DtMetricsHistory,
    DtProject,
)

logger = logging.getLogger(__name__)

_RETRY_STATUS_CODES = {500, 502, 503, 504}


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TimeoutException):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in _RETRY_STATUS_CODES
    return False


def _retry_policy() -> AsyncRetrying:
    return AsyncRetrying(
        retry=retry_if_exception(_is_retryable),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        reraise=True,
    )


class DtHttpClient:
    """Implementa DtClientPort usando httpx con reintentos (tenacity) y control de concurrencia."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        semaphore: asyncio.Semaphore | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._headers = {"X-Api-Key": api_key, "Accept": "application/json"}
        self._semaphore = semaphore or asyncio.Semaphore(5)
        self._timeout = timeout

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    async def _get(self, path: str, **params: Any) -> httpx.Response:
        async for attempt in _retry_policy():
            with attempt:
                async with self._semaphore:
                    async with httpx.AsyncClient(
                        base_url=self._base_url,
                        headers=self._headers,
                        timeout=self._timeout,
                    ) as client:
                        resp = await client.get(path, params=params or None)
                        resp.raise_for_status()
                        return resp
        raise RuntimeError("unreachable")

    # ------------------------------------------------------------------
    # métodos del puerto
    # ------------------------------------------------------------------

    async def get_projects(
        self, page: int = 1, page_size: int = 100
    ) -> tuple[list[DtProject], int]:
        resp = await self._get(
            "/api/v1/project",
            page=page,
            pageSize=page_size,
            excludeInactive="false",
        )
        total = int(resp.headers.get("X-Total-Count", "0"))
        projects = [DtProject.model_validate(p) for p in resp.json()]
        return projects, total

    async def get_all_projects(self) -> list[DtProject]:
        all_projects: list[DtProject] = []
        page = 1
        page_size = 100
        while True:
            batch, total = await self.get_projects(page=page, page_size=page_size)
            all_projects.extend(batch)
            if len(all_projects) >= total or not batch:
                break
            page += 1
        return all_projects

    async def get_project_metrics(self, uuid: str) -> DtMetrics:
        resp = await self._get(f"/api/v1/metrics/project/{uuid}/current")
        return DtMetrics.model_validate(resp.json())

    async def get_project_findings(self, uuid: str) -> list[DtFinding]:
        resp = await self._get(f"/api/v1/finding/project/{uuid}")
        return [DtFinding.model_validate(f) for f in resp.json()]

    async def get_project_metric_history(
        self, uuid: str, days: int = 90
    ) -> list[DtMetricsHistory]:
        resp = await self._get(f"/api/v1/metrics/project/{uuid}/days/{days}")
        return [DtMetricsHistory.model_validate(h) for h in resp.json()]

    async def get_server_version(self) -> str:
        resp = await self._get("/api/v1/about")
        about = DtAbout.model_validate(resp.json())
        return about.version
