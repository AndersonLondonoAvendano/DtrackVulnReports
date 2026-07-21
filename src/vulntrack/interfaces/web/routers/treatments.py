"""T-D035: Router de tratamientos de vulnerabilidades (Iteración 3)."""
from __future__ import annotations

import math
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from vulntrack.application.queries.available_vulnerabilities_query import (
    ListAvailableVulnerabilitiesQuery,
)
from vulntrack.application.treatments.create_treatments import (
    CreateTreatmentsUseCase,
    FindingNotInProjectError,
    TreatmentAlreadyTakenError,
    TreatmentSelection,
)
from vulntrack.application.treatments.generate_top_score_treatments import (
    GenerateTreatmentsFromTopScoreUseCase,
)
from vulntrack.application.treatments.update_treatment import (
    MissingReasonError,
    TreatmentNotFoundError,
    UpdateTreatmentUseCase,
)
from vulntrack.domain.entities.vulnerability_treatment import TreatmentStatus
from vulntrack.domain.services.treatment_transitions import InvalidTreatmentTransitionError
from vulntrack.interfaces.web.dependencies import (
    get_available_vulnerabilities_query,
    get_create_treatments_use_case,
    get_generate_top_score_treatments_use_case,
    get_remediation_repo,
    get_treatment_repo,
    get_update_treatment_use_case,
)
from vulntrack.interfaces.web.schemas.pagination import Page
from vulntrack.interfaces.web.schemas.treatment import (
    AvailableVulnerabilityOut,
    CreateTreatmentsRequest,
    GenerateTreatmentsRequest,
    RemoveTreatmentResult,
    TreatmentOut,
    UpdateTreatmentRequest,
)

router = APIRouter(prefix="/api/v1", tags=["tratamientos"])


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


@router.get(
    "/projects/{project_uuid}/available-vulnerabilities",
    response_model=list[AvailableVulnerabilityOut],
)
async def list_available_vulnerabilities(
    project_uuid: str,
    query: ListAvailableVulnerabilitiesQuery = Depends(  # noqa: B008
        get_available_vulnerabilities_query
    ),
) -> list[AvailableVulnerabilityOut]:
    items = await query.execute(project_uuid)
    return [
        AvailableVulnerabilityOut(
            finding_id=item.finding.id,
            vuln_id=item.finding.vuln_id,
            cve_id=item.finding.cve_id,
            component_name=item.finding.component_name,
            component_version=item.finding.component_version,
            severity=item.finding.severity.value,
            priority_score=item.score.value,
            priority_band=item.score.band.value,
            is_kev=item.score.is_kev,
            previous_no_cumplida_sprint_id=item.previous_no_cumplida_sprint_id,
        )
        for item in items
    ]


@router.post(
    "/remediation/plans/{plan_id}/treatments",
    response_model=list[TreatmentOut],
    status_code=201,
)
async def create_treatments_for_plan(
    plan_id: int,
    body: CreateTreatmentsRequest,
    remediation_repo: Any = Depends(get_remediation_repo),  # noqa: B008
    uc: CreateTreatmentsUseCase = Depends(get_create_treatments_use_case),  # noqa: B008
) -> list[TreatmentOut]:
    plan = await remediation_repo.get_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan no encontrado")

    try:
        treatments = await uc.execute(
            project_uuid=plan.project_uuid,
            sprint_id=body.sprint_id,
            plan_id=plan_id,
            selections=[
                TreatmentSelection(finding_id=s.finding_id, responsable=s.responsable)
                for s in body.selections
            ],
        )
    except TreatmentAlreadyTakenError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except FindingNotInProjectError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return [_treatment_out(t) for t in treatments]


@router.post(
    "/remediation/plans/{plan_id}/treatments/generate",
    response_model=list[TreatmentOut],
    status_code=201,
)
async def generate_treatments_for_plan(
    plan_id: int,
    body: GenerateTreatmentsRequest,
    remediation_repo: Any = Depends(get_remediation_repo),  # noqa: B008
    uc: GenerateTreatmentsFromTopScoreUseCase = Depends(  # noqa: B008
        get_generate_top_score_treatments_use_case
    ),
) -> list[TreatmentOut]:
    plan = await remediation_repo.get_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan no encontrado")

    try:
        treatments = await uc.execute(
            project_uuid=plan.project_uuid,
            plan_id=plan_id,
            sprint_id=body.sprint_id,
            top_n=body.top_n,
        )
    except TreatmentAlreadyTakenError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return [_treatment_out(t) for t in treatments]


@router.delete("/treatments/{treatment_id}", response_model=RemoveTreatmentResult)
async def delete_treatment(
    treatment_id: int,
    repo: Any = Depends(get_treatment_repo),  # noqa: B008
) -> RemoveTreatmentResult:
    existing = await repo.get_by_id(treatment_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Tratamiento no encontrado")
    result = await repo.remove(treatment_id)
    return RemoveTreatmentResult(result=result)


@router.patch("/treatments/{treatment_id}", response_model=TreatmentOut)
async def update_treatment(
    treatment_id: int,
    body: UpdateTreatmentRequest,
    uc: UpdateTreatmentUseCase = Depends(get_update_treatment_use_case),  # noqa: B008
) -> TreatmentOut:
    estado = TreatmentStatus(body.estado) if body.estado else None
    try:
        treatment = await uc.execute(
            treatment_id,
            estado=estado,
            sprint_id=body.sprint_id,
            responsable=body.responsable,
            fecha_objetivo=body.fecha_objetivo,
            notas=body.notas,
            motivo=body.motivo,
        )
    except TreatmentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (MissingReasonError, InvalidTreatmentTransitionError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _treatment_out(treatment)


@router.get("/treatments")
async def list_treatments(
    project_uuid: str,
    sprint_id: int | None = Query(default=None),
    estado: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    repo: Any = Depends(get_treatment_repo),  # noqa: B008
) -> Page[TreatmentOut]:
    estado_enum = TreatmentStatus(estado) if estado else None
    all_items = await repo.list_by_project(project_uuid, sprint_id=sprint_id, estado=estado_enum)
    total = len(all_items)
    start = (page - 1) * page_size
    page_items = all_items[start : start + page_size]
    return Page(
        items=[_treatment_out(t) for t in page_items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=math.ceil(total / page_size) if total > 0 else 1,
    )
