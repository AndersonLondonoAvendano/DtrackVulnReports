"""T-077: Router KEV — estado y refresh del catálogo CISA KEV."""
from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request
from fastapi.responses import HTMLResponse

from vulntrack.application.sync.sync_kev import SyncKevUseCase
from vulntrack.domain.services.kev_matcher import KevMatcher
from vulntrack.interfaces.web._shared import templates
from vulntrack.interfaces.web.dependencies import (
    get_app_settings,
    get_finding_repo,
    get_kev_repo,
    get_project_repo,
    get_sync_kev_use_case,
)
from vulntrack.interfaces.web.schemas.kev import KevFindingOut, KevRefreshOut, KevStatusOut

router = APIRouter(prefix="/api/v1/kev", tags=["kev"])
html_router = APIRouter(tags=["kev-html"])

_kev_refresh_running = False


async def _do_kev_refresh(uc: SyncKevUseCase) -> None:
    global _kev_refresh_running
    _kev_refresh_running = True
    try:
        await uc.execute()
    finally:
        _kev_refresh_running = False


@router.get("/status", response_model=KevStatusOut)
async def kev_status(
    kev_repo: Any = Depends(get_kev_repo),  # noqa: B008
    settings: Any = Depends(get_app_settings),  # noqa: B008
) -> KevStatusOut:
    meta = await kev_repo.get_catalog_meta()
    stale_days = getattr(settings, "kev_stale_days", 7)

    if meta is None:
        return KevStatusOut(
            entries_count=0,
            catalog_date=None,
            last_updated=None,
            is_stale=True,
            stale_threshold_days=stale_days,
        )

    is_stale = False
    if meta.last_fetched_at:
        age = datetime.now(UTC) - meta.last_fetched_at
        is_stale = age > timedelta(days=stale_days)
    else:
        is_stale = True

    return KevStatusOut(
        entries_count=meta.total_entries,
        catalog_date=meta.catalog_updated_at,
        last_updated=meta.last_fetched_at,
        is_stale=is_stale,
        stale_threshold_days=stale_days,
    )


@router.post("/refresh", response_model=KevRefreshOut, status_code=202)
async def refresh_kev(
    background_tasks: BackgroundTasks,
    uc: SyncKevUseCase = Depends(get_sync_kev_use_case),  # noqa: B008
) -> KevRefreshOut:
    if _kev_refresh_running:
        return KevRefreshOut(status="running", message="Actualización KEV ya en curso")
    background_tasks.add_task(_do_kev_refresh, uc)
    return KevRefreshOut(status="started", message="Actualización KEV iniciada en segundo plano")


@router.get("/findings", response_model=list[KevFindingOut])
async def kev_findings(
    kev_repo: Any = Depends(get_kev_repo),  # noqa: B008
    finding_repo: Any = Depends(get_finding_repo),  # noqa: B008
    project_repo: Any = Depends(get_project_repo),  # noqa: B008
) -> list[KevFindingOut]:
    all_kev = await kev_repo.list_all()
    matcher = KevMatcher(all_kev)

    findings = await finding_repo.list_all_active()
    projects = await project_repo.list_all()
    proj_by_uuid = {p.uuid: p for p in projects}

    result = []
    for f in findings:
        kev_entry = matcher.get_kev_details(f.cve_id or f.vuln_id)
        if kev_entry:
            proj = proj_by_uuid.get(f.project_uuid)
            result.append(
                KevFindingOut(
                    vuln_id=f.vuln_id,
                    component_name=f.component_name,
                    component_version=f.component_version,
                    project_name=proj.name if proj else f.project_uuid,
                    severity=f.severity.value,
                    date_added=kev_entry.date_added,
                    required_action=kev_entry.required_action,
                )
            )
    return result


@html_router.get("/kev", response_class=HTMLResponse, include_in_schema=False)
async def kev_html(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    kev_repo: Any = Depends(get_kev_repo),  # noqa: B008
    finding_repo: Any = Depends(get_finding_repo),  # noqa: B008
    project_repo: Any = Depends(get_project_repo),  # noqa: B008
) -> Any:
    meta = await kev_repo.get_catalog_meta()
    all_kev = await kev_repo.list_all()
    matcher = KevMatcher(all_kev)

    findings = await finding_repo.list_all_active()
    projects = await project_repo.list_all()
    proj_by_uuid = {p.uuid: p for p in projects}

    kev_findings = []
    for f in findings:
        kev_entry = matcher.get_kev_details(f.cve_id or f.vuln_id)
        if kev_entry:
            proj = proj_by_uuid.get(f.project_uuid)
            kev_findings.append({
                "vuln_id": f.vuln_id,
                "component_name": f.component_name,
                "component_version": f.component_version,
                "project_name": proj.name if proj else f.project_uuid,
                "severity": f.severity.value,
                "date_added": kev_entry.date_added,
                "required_action": kev_entry.required_action,
            })

    total = len(kev_findings)
    start = (page - 1) * page_size
    paged_kev_findings = kev_findings[start : start + page_size]
    total_pages = math.ceil(total / page_size) if total > 0 else 1

    from vulntrack.config import get_settings as _gs
    stale_days = _gs().kev_stale_days
    is_stale = True
    if meta and meta.last_fetched_at:
        age = datetime.now(UTC) - meta.last_fetched_at
        is_stale = age > timedelta(days=stale_days)

    context = {
        "titulo": "Catálogo KEV",
        "meta": meta,
        "kev_findings": paged_kev_findings,
        "is_stale": is_stale,
        "stale_days": stale_days,
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
    }
    template_name = (
        "partials/kev_findings_table.html"
        if request.headers.get("hx-request") == "true"
        else "kev.html"
    )
    return templates.TemplateResponse(request, template_name, context)
