"""T-078: Router de remediación — planes y tareas."""
from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse

from vulntrack.application.remediation.create_plan import CreatePlanUseCase
from vulntrack.application.remediation.export_plan import ExportFormat, ExportPlanUseCase
from vulntrack.application.remediation.suggest_tasks import SuggestTasksUseCase
from vulntrack.application.remediation.update_task import (
    InvalidTaskTransitionError,
    UpdateTaskUseCase,
)
from vulntrack.domain.entities.remediation import TaskStatus
from vulntrack.domain.exceptions import DomainError
from vulntrack.interfaces.web._shared import templates
from vulntrack.interfaces.web.dependencies import (
    get_create_plan_use_case,
    get_export_plan_use_case,
    get_project_repo,
    get_remediation_repo,
    get_suggest_tasks_use_case,
    get_update_task_use_case,
)
from vulntrack.interfaces.web.schemas.remediation import (
    CreatePlanRequest,
    PlanDetailOut,
    PlanOut,
    TaskOut,
    UpdateTaskRequest,
)

router = APIRouter(prefix="/api/v1/remediation", tags=["remediacion"])
html_router = APIRouter(tags=["remediacion-html"])


def _plan_out(plan: Any) -> PlanOut:
    return PlanOut(
        id=plan.id,
        project_uuid=plan.project_uuid,
        name=plan.name,
        description=plan.description,
        created_at=plan.created_at,
        updated_at=plan.updated_at,
    )


def _task_out(task: Any) -> TaskOut:
    return TaskOut(
        id=task.id,
        plan_id=task.plan_id,
        finding_id=task.finding_id,
        title=task.title,
        description=task.description,
        assignee=task.assignee,
        status=task.status.value if hasattr(task.status, "value") else str(task.status),
        priority_band=task.priority_band.value if hasattr(task.priority_band, "value") else str(task.priority_band),
        recommended_action=task.recommended_action,
        target_date=task.target_date,
        completed_at=task.completed_at,
        notes=task.notes,
        created_at=task.created_at,
    )


@router.post("/plans", response_model=PlanOut, status_code=201)
async def create_plan(
    body: CreatePlanRequest,
    project_uuid: str,
    uc: CreatePlanUseCase = Depends(get_create_plan_use_case),  # noqa: B008
) -> PlanOut:
    plan = await uc.execute(project_uuid, body.name, body.description)
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
) -> PlanDetailOut:
    plan = await repo.get_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan no encontrado")
    tasks = await repo.list_tasks_by_plan(plan_id)
    return PlanDetailOut(plan=_plan_out(plan), tasks=[_task_out(t) for t in tasks])


@router.post("/plans/{plan_id}/suggest", response_model=list[TaskOut])
async def suggest_tasks(
    plan_id: int,
    uc: SuggestTasksUseCase = Depends(get_suggest_tasks_use_case),  # noqa: B008
) -> list[TaskOut]:
    tasks = await uc.execute(plan_id=plan_id)
    return [_task_out(t) for t in tasks]


@router.patch("/tasks/{task_id}", response_model=TaskOut)
async def update_task(
    task_id: int,
    body: UpdateTaskRequest,
    uc: UpdateTaskUseCase = Depends(get_update_task_use_case),  # noqa: B008
) -> TaskOut:
    status = TaskStatus(body.status) if body.status else None
    try:
        task = await uc.execute(
            task_id,
            status=status,
            assignee=body.assignee,
            notes=body.notes,
            target_date=body.target_date,
        )
    except InvalidTaskTransitionError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except DomainError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _task_out(task)


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

@html_router.get("/remediation", response_class=HTMLResponse, include_in_schema=False)
async def remediation_html(
    request: Request,
    repo: Any = Depends(get_remediation_repo),  # noqa: B008
    project_repo: Any = Depends(get_project_repo),  # noqa: B008
) -> Any:
    projects = await project_repo.list_all()
    plans_by_proj = {}
    for p in projects:
        plans = await repo.list_plans_by_project(p.uuid)
        if plans:
            plans_by_proj[p] = plans

    return templates.TemplateResponse(
        request,
        "remediation/list.html",
        {"titulo": "Planes de Remediación", "plans_by_proj": plans_by_proj},
    )


@html_router.get("/remediation/{plan_id}", response_class=HTMLResponse, include_in_schema=False)
async def remediation_detail_html(
    request: Request,
    plan_id: int,
    repo: Any = Depends(get_remediation_repo),  # noqa: B008
) -> Any:
    plan = await repo.get_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan no encontrado")
    tasks = await repo.list_tasks_by_plan(plan_id)
    return templates.TemplateResponse(
        request,
        "remediation/detail.html",
        {"titulo": plan.name, "plan": plan, "tasks": tasks},
    )


