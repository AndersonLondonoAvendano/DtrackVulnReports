"""T-D034/T-D039: Router de sprints (Iteración 3 — flujo de tratamiento por sprints)."""
from __future__ import annotations

import math
from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from vulntrack.application.sprints.close_sprint import (
    CloseSprintUseCase,
    SprintAlreadyClosedError,
    SprintNotFoundError,
)
from vulntrack.application.sprints.create_sprint import CreateSprintUseCase
from vulntrack.application.sprints.update_sprint import UpdateSprintUseCase
from vulntrack.domain.exceptions import DomainError
from vulntrack.interfaces.web._shared import templates
from vulntrack.interfaces.web.dependencies import (
    get_close_sprint_use_case,
    get_create_sprint_use_case,
    get_sprint_repo,
    get_treatment_repo,
    get_update_sprint_use_case,
)
from vulntrack.interfaces.web.schemas.treatment import (
    SprintCreateRequest,
    SprintOut,
    SprintUpdateRequest,
)

router = APIRouter(prefix="/api/v1/sprints", tags=["sprints"])
html_router = APIRouter(tags=["sprints-html"])


def _sprint_out(sprint: Any) -> SprintOut:
    return SprintOut(
        id=sprint.id,
        nombre=sprint.nombre,
        anio=sprint.anio,
        trimestre=sprint.trimestre,
        fecha_inicio=sprint.fecha_inicio,
        fecha_fin=sprint.fecha_fin,
        estado=sprint.estado.value,
        origen=sprint.origen,
        external_id=sprint.external_id,
        created_at=sprint.created_at,
        updated_at=sprint.updated_at,
    )


@router.post("", response_model=SprintOut, status_code=201)
async def create_sprint(
    body: SprintCreateRequest,
    uc: CreateSprintUseCase = Depends(get_create_sprint_use_case),  # noqa: B008
) -> SprintOut:
    try:
        sprint = await uc.execute(
            nombre=body.nombre,
            fecha_inicio=body.fecha_inicio,
            fecha_fin=body.fecha_fin,
            anio=body.anio,
            trimestre=body.trimestre,
            origen=body.origen,
            external_id=body.external_id,
        )
    except DomainError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _sprint_out(sprint)


@router.get("", response_model=list[SprintOut])
async def list_sprints(
    anio: int | None = Query(default=None),
    trimestre: int | None = Query(default=None),
    estado: str | None = Query(default=None),
    repo: Any = Depends(get_sprint_repo),  # noqa: B008
) -> list[SprintOut]:
    sprints = await repo.list_all(anio=anio, trimestre=trimestre, estado=estado)
    return [_sprint_out(s) for s in sprints]


@router.get("/{sprint_id}", response_model=SprintOut)
async def get_sprint(
    sprint_id: int,
    repo: Any = Depends(get_sprint_repo),  # noqa: B008
) -> SprintOut:
    sprint = await repo.get_by_id(sprint_id)
    if sprint is None:
        raise HTTPException(status_code=404, detail="Sprint no encontrado")
    return _sprint_out(sprint)


@router.patch("/{sprint_id}", response_model=SprintOut)
async def update_sprint(
    sprint_id: int,
    body: SprintUpdateRequest,
    uc: UpdateSprintUseCase = Depends(get_update_sprint_use_case),  # noqa: B008
) -> SprintOut:
    try:
        sprint = await uc.execute(
            sprint_id,
            nombre=body.nombre,
            fecha_inicio=body.fecha_inicio,
            fecha_fin=body.fecha_fin,
            external_id=body.external_id,
        )
    except SprintNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DomainError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _sprint_out(sprint)


@router.post("/{sprint_id}/close", response_model=SprintOut)
async def close_sprint(
    sprint_id: int,
    uc: CloseSprintUseCase = Depends(get_close_sprint_use_case),  # noqa: B008
) -> SprintOut:
    try:
        sprint = await uc.execute(sprint_id)
    except SprintNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except SprintAlreadyClosedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _sprint_out(sprint)


# ── T-D039: pantalla HTML "Sprints" ───────────────────────────────────────────


@html_router.get("/sprints", response_class=HTMLResponse, include_in_schema=False)
async def sprints_html(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    sprint_repo: Any = Depends(get_sprint_repo),  # noqa: B008
    treatment_repo: Any = Depends(get_treatment_repo),  # noqa: B008
) -> Any:
    sprints = await sprint_repo.list_all()
    sprints_sorted = sorted(
        sprints, key=lambda s: (s.anio, s.trimestre, s.fecha_inicio), reverse=True
    )

    total = len(sprints_sorted)
    start = (page - 1) * page_size
    paged_sprints = sprints_sorted[start : start + page_size]
    total_pages = math.ceil(total / page_size) if total > 0 else 1

    rows = []
    for s in paged_sprints:
        treatments = await treatment_repo.list_by_sprint(s.id)
        summary: dict[str, int] = {}
        for t in treatments:
            summary[t.estado.value] = summary.get(t.estado.value, 0) + 1
        rows.append({"sprint": s, "total": len(treatments), "summary": summary})

    context = {
        "titulo": "Sprints",
        "rows": rows,
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
    }
    template_name = (
        "partials/sprints_list.html"
        if request.headers.get("hx-request") == "true"
        else "sprints.html"
    )
    return templates.TemplateResponse(request, template_name, context)


@html_router.post("/sprints", include_in_schema=False)
async def create_sprint_form(
    nombre: str = Form(...),
    fecha_inicio: date = Form(...),
    fecha_fin: date = Form(...),
    uc: CreateSprintUseCase = Depends(get_create_sprint_use_case),  # noqa: B008
) -> RedirectResponse:
    try:
        await uc.execute(nombre=nombre, fecha_inicio=fecha_inicio, fecha_fin=fecha_fin)
    except DomainError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return RedirectResponse(url="/sprints", status_code=303)


@html_router.post("/sprints/{sprint_id}/close", include_in_schema=False)
async def close_sprint_form(
    sprint_id: int,
    uc: CloseSprintUseCase = Depends(get_close_sprint_use_case),  # noqa: B008
) -> RedirectResponse:
    try:
        await uc.execute(sprint_id)
    except SprintNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except SprintAlreadyClosedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return RedirectResponse(url="/sprints", status_code=303)
