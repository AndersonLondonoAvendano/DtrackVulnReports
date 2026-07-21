"""T-074: Router de proyectos."""
from __future__ import annotations

import math
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from vulntrack.application.queries.project_detail_query import ProjectDetailQuery
from vulntrack.application.remediation.create_plan import CreatePlanUseCase
from vulntrack.domain.exceptions import ProjectNotFoundError
from vulntrack.interfaces.web._shared import templates
from vulntrack.interfaces.web.dependencies import (
    get_create_plan_use_case,
    get_prioritized_findings_query,
    get_project_detail_query,
    get_project_repo,
)
from vulntrack.interfaces.web.schemas.project import (
    PrioritizedFindingOut,
    ProjectDetailOut,
    ProjectListOut,
    ProjectOut,
    SnapshotOut,
)

router = APIRouter(prefix="/api/v1/projects", tags=["proyectos"])
html_router = APIRouter(tags=["proyectos-html"])


@router.get("", response_model=ProjectListOut)
async def list_projects(
    search: str | None = Query(default=None),
    sort: str = Query(default="name"),
    order: str = Query(default="asc"),
    project_repo: Any = Depends(get_project_repo),  # noqa: B008
) -> ProjectListOut:
    projects = await project_repo.list_all()

    if search:
        projects = [p for p in projects if search.lower() in p.name.lower()]

    reverse = order.lower() == "desc"
    if sort == "name":
        projects.sort(key=lambda p: p.name.lower(), reverse=reverse)

    items = [
        ProjectOut(
            uuid=p.uuid,
            name=p.name,
            version=p.version,
            description=p.description,
            last_synced_at=p.last_synced_at,
        )
        for p in projects
    ]
    return ProjectListOut(items=items, total=len(items))


@router.get("/{uuid}", response_model=ProjectDetailOut)
async def get_project(
    uuid: str,
    query: ProjectDetailQuery = Depends(get_project_detail_query),  # noqa: B008
) -> ProjectDetailOut:
    try:
        detail = await query.execute(uuid)
    except ProjectNotFoundError:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    snapshot_out = None
    if detail.current_snapshot is not None:
        s = detail.current_snapshot
        snapshot_out = SnapshotOut(
            snapshot_date=s.snapshot_date,
            critical=s.critical,
            high=s.high,
            medium=s.medium,
            low=s.low,
            unassigned=s.unassigned,
            total=s.total,
            risk_score=s.risk_score,
        )

    findings = [
        PrioritizedFindingOut(
            finding_id=pf.finding.id,
            vuln_id=pf.finding.vuln_id,
            component_name=pf.finding.component_name,
            component_version=pf.finding.component_version,
            severity=pf.finding.severity.value,
            cvss_v3_base_score=pf.finding.cvss_v3_base_score,
            epss_score=pf.finding.epss_score,
            is_kev=pf.score.is_kev,
            priority_score=pf.score.value,
            priority_band=pf.score.band.value,
        )
        for pf in detail.prioritized_findings
    ]

    open_tasks = sum(1 for t in detail.open_tasks if t.status not in ("COMPLETED", "DISCARDED"))

    return ProjectDetailOut(
        project=ProjectOut(
            uuid=detail.project.uuid,
            name=detail.project.name,
            version=detail.project.version,
            description=detail.project.description,
            last_synced_at=detail.project.last_synced_at,
        ),
        current_snapshot=snapshot_out,
        prioritized_findings=findings,
        open_tasks_count=open_tasks,
    )


# ── HTML routes ───────────────────────────────────────────────────────────────

@html_router.get("/projects", response_class=HTMLResponse, include_in_schema=False)
async def projects_html(
    request: Request,
    search: str | None = Query(default=None),
    sort: str = Query(default="name"),
    order: str = Query(default="asc"),
    project_repo: Any = Depends(get_project_repo),  # noqa: B008
) -> Any:
    projects = await project_repo.list_all()
    if search:
        projects = [p for p in projects if search.lower() in p.name.lower()]
    reverse = order.lower() == "desc"
    if sort == "name":
        projects.sort(key=lambda p: p.name.lower(), reverse=reverse)

    return templates.TemplateResponse(
        request,
        "projects/list.html",
        {"titulo": "Proyectos", "projects": projects, "search": search, "sort": sort, "order": order},
    )


@html_router.get("/projects/{uuid}", response_class=HTMLResponse, include_in_schema=False)
async def project_detail_html(
    request: Request,
    uuid: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    query: ProjectDetailQuery = Depends(get_project_detail_query),  # noqa: B008
) -> Any:
    try:
        detail = await query.execute(uuid)
    except ProjectNotFoundError:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")

    total = len(detail.prioritized_findings)
    start = (page - 1) * page_size
    paged_findings = detail.prioritized_findings[start : start + page_size]
    total_pages = math.ceil(total / page_size) if total > 0 else 1

    context = {
        "titulo": detail.project.name,
        "detail": detail,
        "paged_findings": paged_findings,
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
    }
    template_name = (
        "partials/project_findings_table.html"
        if request.headers.get("hx-request") == "true"
        else "projects/detail.html"
    )
    return templates.TemplateResponse(request, template_name, context)


@html_router.post("/projects/{project_uuid}/remediation/plans", include_in_schema=False)
async def create_remediation_plan_form(
    project_uuid: str,
    name: str = Form(...),
    description: str | None = Form(default=None),
    uc: CreatePlanUseCase = Depends(get_create_plan_use_case),  # noqa: B008
) -> RedirectResponse:
    await uc.execute(project_uuid, name, description or None)
    return RedirectResponse(url=f"/projects/{project_uuid}", status_code=303)
