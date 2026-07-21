"""T-078 / iter4: Router de remediación — planes (los tratamientos viven en
`routers/treatments.py`, T-D035/T-E024/T-E026)."""
from __future__ import annotations

import math
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse

from vulntrack.application.queries.available_vulnerabilities_query import (
    ListAvailableVulnerabilitiesQuery,
)
from vulntrack.application.remediation.create_plan import CreatePlanUseCase, SprintNotFoundError
from vulntrack.application.remediation.export_plan import ExportFormat, ExportPlanUseCase
from vulntrack.application.treatments.create_treatments import (
    CreateTreatmentsUseCase,
    FindingNotInProjectError,
    TreatmentAlreadyTakenError,
    TreatmentSelection,
)
from vulntrack.application.treatments.generate_top_score_treatments import (
    GenerateTreatmentsFromTopScoreUseCase,
)
from vulntrack.domain.exceptions import DomainError
from vulntrack.interfaces.web._shared import templates
from vulntrack.interfaces.web.dependencies import (
    get_available_vulnerabilities_query,
    get_create_plan_use_case,
    get_create_treatments_use_case,
    get_export_plan_use_case,
    get_generate_top_score_treatments_use_case,
    get_project_repo,
    get_remediation_repo,
    get_sprint_repo,
    get_treatment_repo,
)
from vulntrack.interfaces.web.schemas.remediation import (
    CreatePlanRequest,
    PlanDetailOut,
    PlanOut,
)
from vulntrack.interfaces.web.schemas.treatment import TreatmentOut

router = APIRouter(prefix="/api/v1/remediation", tags=["remediacion"])
html_router = APIRouter(tags=["remediacion-html"])


def _plan_out(plan: Any) -> PlanOut:
    return PlanOut(
        id=plan.id,
        project_uuid=plan.project_uuid,
        name=plan.name,
        description=plan.description,
        sprint_id=plan.sprint_id,
        created_at=plan.created_at,
        updated_at=plan.updated_at,
    )


def _treatment_out(t: Any) -> TreatmentOut:
    return TreatmentOut(
        id=t.id,
        project_uuid=t.project_uuid,
        vuln_key=t.vuln_key,
        cve_id=t.cve_id,
        finding_id=t.finding_id,
        plan_id=t.plan_id,
        sprint_id=t.sprint_id,
        responsable=t.responsable,
        estado=t.estado.value,
        priority_band=t.priority_band.value,
        fecha_creacion=t.fecha_creacion,
        fecha_objetivo=t.fecha_objetivo,
        fecha_cierre=t.fecha_cierre,
        notas=t.notas,
        motivo=t.motivo,
        recurrence_flag=t.recurrence_flag,
        recurrence_count=t.recurrence_count,
        last_recurrence_at=t.last_recurrence_at,
        created_at=t.created_at,
        updated_at=t.updated_at,
        component_name=t.component_name,
        component_version=t.component_version,
        finalizacion_subtipo=t.finalizacion_subtipo,
        activo_en_plan=t.activo_en_plan,
    )


@router.post("/plans", response_model=PlanOut, status_code=201)
async def create_plan(
    body: CreatePlanRequest,
    project_uuid: str,
    uc: CreatePlanUseCase = Depends(get_create_plan_use_case),  # noqa: B008
) -> PlanOut:
    try:
        plan = await uc.execute(project_uuid, body.name, body.description, body.sprint_id)
    except SprintNotFoundError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _plan_out(plan)


@router.get("/plans/{project_uuid}", response_model=list[PlanOut])
async def list_plans(
    project_uuid: str,
    repo: Any = Depends(get_remediation_repo),  # noqa: B008
) -> list[PlanOut]:
    plans = await repo.list_plans_by_project(project_uuid)
    return [_plan_out(p) for p in plans]


@router.get("/plans/{plan_id}/detail", response_model=PlanDetailOut)
async def get_plan_detail(
    plan_id: int,
    repo: Any = Depends(get_remediation_repo),  # noqa: B008
    treatment_repo: Any = Depends(get_treatment_repo),  # noqa: B008
) -> PlanDetailOut:
    plan = await repo.get_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan no encontrado")
    all_treatments = await treatment_repo.list_by_project(plan.project_uuid)
    treatments = [t for t in all_treatments if t.plan_id == plan_id]
    return PlanDetailOut(plan=_plan_out(plan), treatments=[_treatment_out(t) for t in treatments])


@router.post("/plans/{plan_id}/export")
async def export_plan(
    plan_id: int,
    fmt: str = "xlsx",
    uc: ExportPlanUseCase = Depends(get_export_plan_use_case),  # noqa: B008
) -> StreamingResponse:
    try:
        export_fmt = ExportFormat(fmt)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Formato inválido: {fmt}")

    try:
        data = await uc.execute(plan_id, export_fmt)
    except DomainError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    mime = (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        if export_fmt == ExportFormat.XLSX
        else "application/pdf"
    )
    import io
    return StreamingResponse(
        io.BytesIO(data),
        media_type=mime,
        headers={"Content-Disposition": f'attachment; filename="plan_{plan_id}.{fmt}"'},
    )


# ── HTML routes ───────────────────────────────────────────────────────────────

_PAGE_SIZE_DEFAULT = 25


@html_router.get("/remediation", response_class=HTMLResponse, include_in_schema=False)
async def remediation_html(
    request: Request,
    project_uuid: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=_PAGE_SIZE_DEFAULT, ge=1, le=100),
    repo: Any = Depends(get_remediation_repo),  # noqa: B008
    project_repo: Any = Depends(get_project_repo),  # noqa: B008
    sprint_repo: Any = Depends(get_sprint_repo),  # noqa: B008
) -> Any:
    projects = await project_repo.list_all()
    filtered_projects = (
        [p for p in projects if p.uuid == project_uuid] if project_uuid else projects
    )

    rows = []
    for p in filtered_projects:
        plans = await repo.list_plans_by_project(p.uuid)
        for plan in plans:
            rows.append({"plan": plan, "project": p})
    rows.sort(key=lambda r: r["plan"].created_at, reverse=True)

    total = len(rows)
    start = (page - 1) * page_size
    paged_rows = rows[start : start + page_size]
    total_pages = math.ceil(total / page_size) if total > 0 else 1

    sprints = await sprint_repo.list_all()

    context = {
        "titulo": "Planes de Remediación",
        "rows": paged_rows,
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
        "project_uuid": project_uuid,
        "projects": projects,
        "sprints": sprints,
    }
    template_name = (
        "partials/remediation_plans_table.html"
        if request.headers.get("hx-request") == "true"
        else "remediation/list.html"
    )
    return templates.TemplateResponse(request, template_name, context)


@html_router.post("/remediation", include_in_schema=False)
async def create_plan_form(
    project_uuid: str = Form(...),
    name: str = Form(...),
    sprint_id: int = Form(...),
    description: str | None = Form(default=None),
    uc: CreatePlanUseCase = Depends(get_create_plan_use_case),  # noqa: B008
) -> RedirectResponse:
    try:
        plan = await uc.execute(project_uuid, name, description or None, sprint_id)
    except SprintNotFoundError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return RedirectResponse(url=f"/remediation/{plan.id}", status_code=303)


@html_router.get("/remediation/{plan_id}", response_class=HTMLResponse, include_in_schema=False)
async def remediation_detail_html(
    request: Request,
    plan_id: int,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=_PAGE_SIZE_DEFAULT, ge=1, le=100),
    repo: Any = Depends(get_remediation_repo),  # noqa: B008
    treatment_repo: Any = Depends(get_treatment_repo),  # noqa: B008
) -> Any:
    plan = await repo.get_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan no encontrado")

    all_treatments = await treatment_repo.list_by_project(plan.project_uuid)
    treatments = [t for t in all_treatments if t.plan_id == plan_id]
    treatments.sort(key=lambda t: t.fecha_creacion, reverse=True)

    total = len(treatments)
    start = (page - 1) * page_size
    paged_treatments = treatments[start : start + page_size]
    total_pages = math.ceil(total / page_size) if total > 0 else 1

    context = {
        "titulo": plan.name,
        "plan": plan,
        "treatments": paged_treatments,
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
    }
    template_name = (
        "partials/remediation_treatments_table.html"
        if request.headers.get("hx-request") == "true"
        else "remediation/detail.html"
    )
    return templates.TemplateResponse(request, template_name, context)


@html_router.get(
    "/remediation/plans/{plan_id}/available-vulnerabilities-modal",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def available_vulnerabilities_modal_html(
    request: Request,
    plan_id: int,
    repo: Any = Depends(get_remediation_repo),  # noqa: B008
    query: ListAvailableVulnerabilitiesQuery = Depends(  # noqa: B008
        get_available_vulnerabilities_query
    ),
) -> Any:
    plan = await repo.get_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan no encontrado")
    items = await query.execute(plan.project_uuid)
    return templates.TemplateResponse(
        request,
        "partials/available_vulnerabilities_modal.html",
        {"plan": plan, "items": items},
    )


@html_router.post("/remediation/plans/{plan_id}/treatments-form", include_in_schema=False)
async def create_treatments_form(
    request: Request,
    plan_id: int,
    finding_ids: list[int] = Form(default=[]),  # noqa: B008
    repo: Any = Depends(get_remediation_repo),  # noqa: B008
    create_treatments_uc: CreateTreatmentsUseCase = Depends(  # noqa: B008
        get_create_treatments_use_case
    ),
) -> RedirectResponse:
    plan = await repo.get_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan no encontrado")
    if plan.sprint_id is None:
        raise HTTPException(status_code=422, detail="El plan no tiene sprint asignado")

    if finding_ids:
        form = await request.form()
        selections = [
            TreatmentSelection(
                finding_id=fid,
                responsable=(str(form[f"responsable_{fid}"]) or None)
                if form.get(f"responsable_{fid}")
                else None,
            )
            for fid in finding_ids
        ]
        try:
            await create_treatments_uc.execute(
                project_uuid=plan.project_uuid,
                sprint_id=plan.sprint_id,
                plan_id=plan_id,
                selections=selections,
            )
        except TreatmentAlreadyTakenError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except FindingNotInProjectError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    return RedirectResponse(url=f"/remediation/{plan_id}", status_code=303)


@html_router.post(
    "/remediation/plans/{plan_id}/treatments/generate-form", include_in_schema=False
)
async def generate_treatments_form(
    plan_id: int,
    top_n: int = Form(default=10),
    repo: Any = Depends(get_remediation_repo),  # noqa: B008
    uc: GenerateTreatmentsFromTopScoreUseCase = Depends(  # noqa: B008
        get_generate_top_score_treatments_use_case
    ),
) -> RedirectResponse:
    plan = await repo.get_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan no encontrado")
    if plan.sprint_id is None:
        raise HTTPException(status_code=422, detail="El plan no tiene sprint asignado")

    top_n = max(1, min(top_n, 100))
    try:
        await uc.execute(
            project_uuid=plan.project_uuid,
            plan_id=plan_id,
            sprint_id=plan.sprint_id,
            top_n=top_n,
        )
    except TreatmentAlreadyTakenError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return RedirectResponse(url=f"/remediation/{plan_id}", status_code=303)
