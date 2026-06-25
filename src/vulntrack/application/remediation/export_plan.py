"""T-067: Caso de uso ExportPlan — exporta plan de remediación en .xlsx o .pdf."""
from __future__ import annotations

from enum import StrEnum

from vulntrack.domain.entities.remediation import RemediationPlan, RemediationTask
from vulntrack.domain.exceptions import DomainError
from vulntrack.domain.ports.remediation_repository import RemediationRepository


class ExportFormat(StrEnum):
    XLSX = "xlsx"
    PDF = "pdf"


class PlanNotFoundError(DomainError):
    def __init__(self, plan_id: int) -> None:
        super().__init__(f"Plan de remediación {plan_id} no encontrado")


class ExportPlanUseCase:
    def __init__(self, repo: RemediationRepository) -> None:
        self._repo = repo

    async def execute(self, plan_id: int, fmt: ExportFormat) -> bytes:
        plan = await self._repo.get_plan(plan_id)
        if plan is None:
            raise PlanNotFoundError(plan_id)

        tasks = await self._repo.list_tasks_by_plan(plan_id)

        if fmt == ExportFormat.XLSX:
            return _export_xlsx(plan, tasks)
        return _export_pdf(plan, tasks)


def _export_xlsx(plan: RemediationPlan, tasks: list[RemediationTask]) -> bytes:
    import io

    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill

    wb = Workbook()
    ws = wb.active
    ws.title = "Plan de Remediación"  # type: ignore[union-attr]

    # Header
    header_fill = PatternFill("solid", fgColor="1F3864")
    header_font = Font(bold=True, color="FFFFFF", size=11)
    headers = [
        "ID", "Título", "Estado", "Prioridad", "Asignado a",
        "Fecha objetivo", "Acción recomendada", "Notas",
    ]
    for col, h in enumerate(headers, start=1):
        cell = ws.cell(row=1, column=col, value=h)  # type: ignore[union-attr]
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center")

    # Rows
    for row_idx, task in enumerate(tasks, start=2):
        ws.cell(row=row_idx, column=1, value=task.id)  # type: ignore[union-attr]
        ws.cell(row=row_idx, column=2, value=task.title)  # type: ignore[union-attr]
        ws.cell(row=row_idx, column=3, value=task.status)  # type: ignore[union-attr]
        ws.cell(row=row_idx, column=4, value=task.priority_band)  # type: ignore[union-attr]
        ws.cell(row=row_idx, column=5, value=task.assignee or "")  # type: ignore[union-attr]
        ws.cell(row=row_idx, column=6, value=str(task.target_date) if task.target_date else "")  # type: ignore[union-attr]
        ws.cell(row=row_idx, column=7, value=task.recommended_action or "")  # type: ignore[union-attr]
        ws.cell(row=row_idx, column=8, value=task.notes or "")  # type: ignore[union-attr]

    # Autowidth
    for col_cells in ws.columns:  # type: ignore[union-attr]
        max_len = max((len(str(c.value or "")) for c in col_cells), default=10)
        ws.column_dimensions[col_cells[0].column_letter].width = min(max_len + 2, 45)  # type: ignore[union-attr]

    ws.freeze_panes = "A2"  # type: ignore[union-attr]

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf.read()


def _export_pdf(plan: RemediationPlan, tasks: list[RemediationTask]) -> bytes:
    from jinja2 import Environment, PackageLoader

    rows_html = "".join(
        f"<tr><td>{t.id}</td><td>{t.title}</td><td>{t.status}</td>"
        f"<td>{t.priority_band}</td><td>{t.assignee or ''}</td>"
        f"<td>{t.target_date or ''}</td><td>{t.recommended_action or ''}</td></tr>"
        for t in tasks
    )
    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
@page {{ size: A4; margin: 2cm; }}
body {{ font-family: sans-serif; font-size: 10px; }}
h1 {{ color: #1F3864; font-size: 16px; }}
h2 {{ color: #1F3864; font-size: 12px; margin-top: 8px; }}
table {{ border-collapse: collapse; width: 100%; }}
th {{ background: #1F3864; color: white; padding: 4px 6px; text-align: left; font-size: 9px; }}
td {{ border: 1px solid #ccc; padding: 3px 5px; font-size: 9px; }}
</style>
</head>
<body>
<h1>Plan de Remediación: {plan.name}</h1>
<h2>Proyecto: {plan.project_uuid}</h2>
<p>Generado: {plan.updated_at.strftime('%Y-%m-%d %H:%M')}</p>
<table>
<tr>
<th>ID</th><th>Título</th><th>Estado</th><th>Prioridad</th>
<th>Asignado</th><th>Fecha objetivo</th><th>Acción recomendada</th>
</tr>
{rows_html}
</table>
</body></html>"""

    from weasyprint import HTML

    pdf = HTML(string=html).write_pdf()
    return pdf  # type: ignore[return-value]
