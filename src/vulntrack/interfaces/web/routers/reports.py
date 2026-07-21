"""T-075: Router de reportes — generación y descarga."""
from __future__ import annotations

import io
import zipfile
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse

from vulntrack.application.reports.generate_portfolio_report import (
    GeneratePortfolioReportUseCase,
    ReportFormat,
)
from vulntrack.domain.value_objects.date_range import DateRange
from vulntrack.domain.value_objects.report_period import ReportPeriod
from vulntrack.interfaces.web._shared import templates
from vulntrack.interfaces.web.dependencies import (
    get_generate_portfolio_use_case,
    is_pdf_generation_available,
)
from vulntrack.interfaces.web.schemas.report import GenerateReportRequest

router = APIRouter(prefix="/api/v1/reports", tags=["reportes"])
html_router = APIRouter(tags=["reportes-html"])

_MIME = {
    ReportFormat.DOCX: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ReportFormat.XLSX: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ReportFormat.PDF: "application/pdf",
}


def _build_date_range(req: GenerateReportRequest) -> tuple[DateRange, str]:
    if req.period == "custom":
        dr = DateRange(req.date_from, req.date_to)  # type: ignore[arg-type]
        label = f"{req.date_from} — {req.date_to}"
    elif req.period == "quarterly":
        dr = ReportPeriod.resolve(
            ReportPeriod.QUARTERLY,
            year=req.year,
            quarter=req.quarter,
        )
        label = f"{req.quarter} {req.year}"
    else:
        dr = ReportPeriod.resolve(ReportPeriod.MONTHLY, year=req.year, month=None)
        label = f"{req.year}"
    return dr, label


@router.post("/generate")
async def generate_report(
    body: GenerateReportRequest,
    uc: GeneratePortfolioReportUseCase = Depends(get_generate_portfolio_use_case),  # noqa: B008
) -> StreamingResponse:
    try:
        date_range, label = _build_date_range(body)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    formats = [ReportFormat(f) for f in body.formats if f in ReportFormat._value2member_map_]
    if not formats:
        raise HTTPException(status_code=422, detail="Sin formatos válidos")

    results = await uc.execute(date_range=date_range, period_label=label, formats=formats)

    if not results:
        requested = ", ".join(f.value.upper() for f in formats)
        raise HTTPException(
            status_code=422,
            detail=(
                f"Ninguno de los formatos solicitados ({requested}) está disponible en este servidor. "
                f"PDF requiere WeasyPrint/GTK instalado. Pruebe con DOCX o XLSX."
            ),
        )

    safe_label = label.replace(" ", "_").replace("/", "-")

    if len(results) == 1:
        fmt, data = next(iter(results.items()))
        filename = f"Reporte_Portafolio_{safe_label}.{fmt.value}"
        return StreamingResponse(
            io.BytesIO(data),
            media_type=_MIME[fmt],
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # Múltiples formatos → ZIP
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fmt, data in results.items():
            zf.writestr(f"Reporte_Portafolio_{safe_label}.{fmt.value}", data)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="Reporte_Portafolio_{safe_label}.zip"'
        },
    )


@html_router.get("/reports", response_class=HTMLResponse, include_in_schema=False)
async def reports_html(request: Request) -> Any:
    from datetime import date
    current_year = date.today().year
    return templates.TemplateResponse(
        request,
        "reports.html",
        {
            "titulo": "Generar Reporte",
            "current_year": current_year,
            "years": list(range(current_year - 3, current_year + 1)),
            "pdf_available": is_pdf_generation_available(),
        },
    )
