"""T-076: Router de priorización de hallazgos."""
from __future__ import annotations

import math
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse

from vulntrack.application.queries.prioritized_findings_query import (
    PrioritizedFindingsQuery,
    TreatmentSummary,
)
from vulntrack.interfaces.web._shared import templates
from vulntrack.interfaces.web.dependencies import get_prioritized_findings_query, get_sprint_repo
from vulntrack.interfaces.web.query_params import (
    OptionalFloatQuery,
    OptionalIntQuery,
    OptionalStrQuery,
)
from vulntrack.interfaces.web.schemas.pagination import Page
from vulntrack.interfaces.web.schemas.project import PrioritizedFindingOut
from vulntrack.interfaces.web.schemas.treatment import TreatmentSummaryOut

router = APIRouter(prefix="/api/v1/findings", tags=["priorizacion"])
html_router = APIRouter(tags=["priorizacion-html"])


def _treatment_summary_out(t: TreatmentSummary | None) -> TreatmentSummaryOut | None:
    if t is None:
        return None
    return TreatmentSummaryOut(
        treatment_id=t.treatment_id,
        sprint_id=t.sprint_id,
        sprint_nombre=t.sprint_nombre,
        estado=t.estado,
        responsable=t.responsable,
        fecha_objetivo=t.fecha_objetivo,
    )


@router.get("/prioritized")
async def get_prioritized_findings(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    kev_only: bool = Query(default=False),
    min_cvss: OptionalFloatQuery = None,
    min_epss: OptionalFloatQuery = None,
    sprint_id: OptionalIntQuery = None,
    treatment_status: OptionalStrQuery = None,
    query: PrioritizedFindingsQuery = Depends(get_prioritized_findings_query),  # noqa: B008
) -> Page[PrioritizedFindingOut]:
    all_items = await query.execute(
        kev_only=kev_only,
        min_cvss=min_cvss,
        min_epss=min_epss,
        sprint_id=sprint_id,
        treatment_status=treatment_status,
    )
    total = len(all_items)
    start = (page - 1) * page_size
    page_items = all_items[start : start + page_size]
    out = [
        PrioritizedFindingOut(
            finding_id=item.finding.id,
            vuln_id=item.finding.vuln_id,
            project_uuid=item.finding.project_uuid,
            project_name=item.project_name,
            component_name=item.finding.component_name,
            component_version=item.finding.component_version,
            severity=item.finding.severity.value,
            cvss_v3_base_score=item.finding.cvss_v3_base_score,
            epss_score=item.finding.epss_score,
            is_kev=item.score.is_kev,
            priority_score=round(item.score.value, 2),
            priority_band=item.score.band.value,
            treatment=_treatment_summary_out(item.treatment),
        )
        for item in page_items
    ]
    return Page(
        items=out,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=math.ceil(total / page_size) if total > 0 else 1,
    )


@router.get("/thresholds")
async def get_thresholds() -> dict[str, Any]:
    return {
        "kev_minimum_score": 75.0,
        "bands": {
            "CRITICAL": {"min": 75, "max": 100, "label": "Inmediata"},
            "HIGH": {"min": 50, "max": 74, "label": "Alta"},
            "MEDIUM": {"min": 25, "max": 49, "label": "Media"},
            "LOW": {"min": 0, "max": 24, "label": "Baja"},
        },
    }


@html_router.get("/prioritization", response_class=HTMLResponse, include_in_schema=False)
async def prioritization_html(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    kev_only: bool = Query(default=False),
    min_cvss: OptionalFloatQuery = None,
    min_epss: OptionalFloatQuery = None,
    sprint_id: OptionalIntQuery = None,
    treatment_status: OptionalStrQuery = None,
    query: PrioritizedFindingsQuery = Depends(get_prioritized_findings_query),  # noqa: B008
    sprint_repo: Any = Depends(get_sprint_repo),  # noqa: B008
) -> Any:
    all_items = await query.execute(
        kev_only=kev_only,
        min_cvss=min_cvss,
        min_epss=min_epss,
        sprint_id=sprint_id,
        treatment_status=treatment_status,
    )
    total = len(all_items)
    start = (page - 1) * page_size
    items = all_items[start : start + page_size]
    total_pages = math.ceil(total / page_size) if total > 0 else 1
    sprints = await sprint_repo.list_all()
    context = {
        "titulo": "Priorización de Hallazgos",
        "items": items,
        "kev_only": kev_only,
        "min_cvss": min_cvss,
        "min_epss": min_epss,
        "sprint_id": sprint_id,
        "treatment_status": treatment_status,
        "sprints": sprints,
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
    }
    template_name = (
        "partials/prioritization_findings_table.html"
        if request.headers.get("hx-request") == "true"
        else "prioritization.html"
    )
    return templates.TemplateResponse(request, template_name, context)
