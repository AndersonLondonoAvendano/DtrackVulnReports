"""T-054: Generador de reportes PDF (WeasyPrint + Jinja2)."""
from __future__ import annotations

import base64
import io
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

from vulntrack.domain.value_objects.severity import Severity
from vulntrack.infrastructure.reports.chart_builder import ChartBuilder, ReportData

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_SEV_LABELS: dict[str, str] = {
    "CRITICAL": "Crítica",
    "HIGH": "Alta",
    "MEDIUM": "Media",
    "LOW": "Baja",
    "UNASSIGNED": "Sin asignar",
}

# Mapeado con valores de enum para Jinja
_SEV_LABELS_ENUM: dict[Severity, str] = {
    Severity.CRITICAL: "Crítica",
    Severity.HIGH: "Alta",
    Severity.MEDIUM: "Media",
    Severity.LOW: "Baja",
    Severity.UNASSIGNED: "Sin asignar",
}


def _buf_to_b64(buf: io.BytesIO) -> str:
    return base64.b64encode(buf.read()).decode("ascii")


def _build_observations(data: ReportData) -> list[str]:
    obs: list[str] = []

    criticas = data.portfolio_metrics.get(Severity.CRITICAL, 0)
    if criticas > 0:
        obs.append(
            f"Existen {criticas} vulnerabilidades críticas vigentes que requieren atención inmediata."
        )

    kev_count = len(data.kev_hits)
    if kev_count > 0:
        obs.append(
            f"Se identificaron {kev_count} vulnerabilidades en el catálogo CISA KEV con exploits "
            "activos confirmados. Se recomienda su remediación en un plazo máximo de 7 días."
        )

    if data.total_tratadas > 0:
        pct = (data.total_tratadas / max(data.total_vigentes + data.total_tratadas, 1)) * 100
        obs.append(
            f"Durante el período se trató el {pct:.0f}% de las vulnerabilidades detectadas "
            f"({data.total_tratadas} de {data.total_vigentes + data.total_tratadas})."
        )

    if not obs:
        obs.append(
            "No se registraron vulnerabilidades críticas en el período. "
            "Continuar con el monitoreo periódico."
        )

    return obs


class PdfGenerator:
    """Implementa ReportGenerator para generar reportes PDF vía WeasyPrint."""

    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=True,
        )

    def generate(self, data: ReportData) -> bytes:
        builder = ChartBuilder()

        # Generar gráficas y convertir a base64
        charts: dict[str, str] = {}

        donut_vig = builder.donut_by_severity(
            data.portfolio_metrics, "Distribución vigentes"
        )
        charts["donut_vigentes"] = _buf_to_b64(donut_vig)

        if data.project_rows:
            bars_vig = builder.horizontal_bars_by_project(
                data.project_rows, "Vigentes por proyecto"
            )
            charts["bars_vigentes"] = _buf_to_b64(bars_vig)

        donut_new = builder.donut_by_severity(
            data.new_portfolio_metrics, "Distribución nuevas"
        )
        charts["donut_nuevas"] = _buf_to_b64(donut_new)

        if data.evolution_rows:
            div = builder.divergent_bars_evolution(
                data.evolution_rows, "Variación"
            )
            charts["divergent"] = _buf_to_b64(div)

            grp = builder.grouped_bars_inicio_vs_actual(
                data.evolution_rows, "Inicio vs Actual"
            )
            charts["grouped"] = _buf_to_b64(grp)

        if data.quarterly_progress is not None:
            qp = data.quarterly_progress
            progress_buf = builder.quarterly_progress_bars(
                qp, f"Avance de remediación — {qp.anio}-Q{qp.trimestre}"
            )
            charts["quarterly_progress"] = _buf_to_b64(progress_buf)

        observations = _build_observations(data)

        template = self._env.get_template("report_pdf.html")
        html_str = template.render(
            data=data,
            charts=charts,
            sev_labels=_SEV_LABELS_ENUM,
            observations=observations,
        )

        pdf_bytes = HTML(string=html_str).write_pdf()
        return pdf_bytes  # type: ignore[return-value]
