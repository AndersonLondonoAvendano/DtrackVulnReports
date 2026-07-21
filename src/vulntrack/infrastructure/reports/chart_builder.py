from __future__ import annotations

import io
from dataclasses import dataclass, field
from datetime import date, datetime

import matplotlib
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

from vulntrack.domain.value_objects.priority_score import PriorityBand
from vulntrack.domain.value_objects.severity import Severity

matplotlib.use("Agg")

# ─── Row types ────────────────────────────────────────────────────────────────


@dataclass
class ProjectRow:
    name: str
    critical: int
    high: int
    medium: int
    low: int
    unassigned: int
    total: int
    risk_score: float


@dataclass
class EvolutionRow:
    name: str
    inicio: int
    actual: int
    variacion: int
    tratadas: int


@dataclass
class PrioritizedFindingRow:
    vuln_id: str
    component_name: str
    component_version: str | None
    project_name: str
    severity: Severity
    cvss_v3_base_score: float | None
    epss_score: float | None
    is_kev: bool
    priority_score: float
    priority_band: PriorityBand


@dataclass
class QuarterlySprintTrendRow:
    sprint_nombre: str
    entraron: int
    resueltas: int
    pospuestas: int
    no_cumplidas: int
    en_curso: int
    descartadas: int


@dataclass
class QuarterlyProgressData:
    """T-D048: sección 'Avance de remediación por Q' -- réplica desacoplada de
    `QuarterlyMetrics` (application layer) para no romper la dirección de
    dependencias (infra/reports sólo depende de domain, no de application)."""

    anio: int
    trimestre: int
    entraron: int
    resueltas: int
    pospuestas: int
    no_cumplidas: int
    en_curso: int
    descartadas: int
    pct_cumplimiento: float | None
    tendencia_por_sprint: list[QuarterlySprintTrendRow] = field(default_factory=list)


# ─── Report data ──────────────────────────────────────────────────────────────


@dataclass
class ReportData:
    period_label: str
    date_from: date
    date_to: date
    generated_at: datetime
    author: str

    # KPIs de portafolio
    total_vigentes: int
    total_nuevas: int
    total_tratadas: int
    risk_score_portfolio: float

    # Distribución vigentes por severidad
    portfolio_metrics: dict[Severity, int] = field(default_factory=dict)

    # Distribución nuevas por severidad
    new_portfolio_metrics: dict[Severity, int] = field(default_factory=dict)

    # Tablas
    project_rows: list[ProjectRow] = field(default_factory=list)
    evolution_rows: list[EvolutionRow] = field(default_factory=list)
    prioritized_findings: list[PrioritizedFindingRow] = field(default_factory=list)
    kev_hits: list[PrioritizedFindingRow] = field(default_factory=list)

    # T-D048: avance de remediación por Q (opcional -- None si no hay
    # sprints/tratamientos, o si los repos no fueron provistos a BuildReportDataUseCase).
    quarterly_progress: QuarterlyProgressData | None = None


# ─── Palette ──────────────────────────────────────────────────────────────────

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "#C00000",
    Severity.HIGH: "#FF0000",
    Severity.MEDIUM: "#FF9900",
    Severity.LOW: "#FFFF00",
    Severity.UNASSIGNED: "#D9D9D9",
}

_SEVERITY_LABELS: dict[Severity, str] = {
    Severity.CRITICAL: "Crítica",
    Severity.HIGH: "Alta",
    Severity.MEDIUM: "Media",
    Severity.LOW: "Baja",
    Severity.UNASSIGNED: "Sin asignar",
}


# ─── ChartBuilder ─────────────────────────────────────────────────────────────


class ChartBuilder:
    """Genera gráficas como PNG en BytesIO. Sin dependencias de BD ni framework."""

    def donut_by_severity(self, counts: dict[Severity, int], title: str) -> io.BytesIO:
        severities = [s for s in Severity if counts.get(s, 0) > 0]
        values = [counts[s] for s in severities]
        colors = [_SEVERITY_COLORS[s] for s in severities]
        labels = [_SEVERITY_LABELS[s] for s in severities]

        fig, ax = plt.subplots(figsize=(5, 4), dpi=110)

        if not values or sum(values) == 0:
            ax.text(
                0.5, 0.5, "Sin datos", ha="center", va="center",
                transform=ax.transAxes, fontsize=12,
            )
            ax.axis("off")
        else:
            total = sum(values)
            wedges, _ = ax.pie(
                values,
                colors=colors,
                startangle=90,
                wedgeprops={"width": 0.55, "edgecolor": "white", "linewidth": 1.5},
            )
            ax.text(
                0, 0, str(total), ha="center", va="center",
                fontsize=18, fontweight="bold", color="#1F3864",
            )
            ax.legend(
                wedges,
                [f"{l} ({v})" for l, v in zip(labels, values)],
                loc="lower center",
                bbox_to_anchor=(0.5, -0.15),
                ncol=3,
                fontsize=8,
                frameon=False,
            )

        ax.set_title(title, fontsize=11, fontweight="bold", color="#1F3864", pad=8)
        fig.tight_layout()
        buf = io.BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight")
        plt.close(fig)
        buf.seek(0)
        return buf

    def horizontal_bars_by_project(
        self, rows: list[ProjectRow], title: str
    ) -> io.BytesIO:
        if not rows:
            return self._empty_chart(title)

        names = [r.name[:30] for r in rows]
        severities_ordered = [
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
            Severity.LOW, Severity.UNASSIGNED,
        ]
        height = max(3.5, len(rows) * 0.45 + 1.5)
        fig, ax = plt.subplots(figsize=(8, height), dpi=110)

        lefts = [0.0] * len(rows)
        for sev in severities_ordered:
            vals = [getattr(r, sev.lower(), 0) for r in rows]
            bars = ax.barh(
                names, vals, left=lefts,
                color=_SEVERITY_COLORS[sev], label=_SEVERITY_LABELS[sev],
                height=0.6,
            )
            for bar, val, left in zip(bars, vals, lefts):
                if val > 0:
                    ax.text(
                        left + val / 2,
                        bar.get_y() + bar.get_height() / 2,
                        str(val), ha="center", va="center", fontsize=7, color="black",
                    )
            lefts = [l + v for l, v in zip(lefts, vals)]

        for i, total in enumerate([r.total for r in rows]):
            ax.text(
                lefts[i] + 0.5, i, str(total),
                ha="left", va="center", fontsize=8, fontweight="bold",
            )

        ax.set_title(title, fontsize=11, fontweight="bold", color="#1F3864")
        ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
        ax.legend(
            loc="lower right", fontsize=8, frameon=False, ncol=3,
            bbox_to_anchor=(1.0, -0.18),
        )
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        fig.tight_layout()
        buf = io.BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight")
        plt.close(fig)
        buf.seek(0)
        return buf

    def divergent_bars_evolution(
        self, rows: list[EvolutionRow], title: str
    ) -> io.BytesIO:
        if not rows:
            return self._empty_chart(title)

        names = [r.name[:30] for r in rows]
        variaciones = [r.variacion for r in rows]
        colors = ["#C00000" if v > 0 else "#70AD47" for v in variaciones]

        height = max(3.5, len(rows) * 0.45 + 1.5)
        fig, ax = plt.subplots(figsize=(7, height), dpi=110)

        bars = ax.barh(names, variaciones, color=colors, height=0.6)
        ax.axvline(0, color="black", linewidth=0.8)

        for bar, val in zip(bars, variaciones):
            offset = 0.2 if val >= 0 else -0.2
            ha = "left" if val >= 0 else "right"
            ax.text(
                val + offset,
                bar.get_y() + bar.get_height() / 2,
                f"{val:+d}", ha=ha, va="center", fontsize=8,
            )

        ax.set_title(title, fontsize=11, fontweight="bold", color="#1F3864")
        ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        fig.tight_layout()
        buf = io.BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight")
        plt.close(fig)
        buf.seek(0)
        return buf

    def grouped_bars_inicio_vs_actual(
        self, rows: list[EvolutionRow], title: str
    ) -> io.BytesIO:
        if not rows:
            return self._empty_chart(title)

        names = [r.name[:30] for r in rows]
        inicios = [r.inicio for r in rows]
        actuales = [r.actual for r in rows]

        x = range(len(rows))
        width = 0.38
        height = max(4.0, len(rows) * 0.5 + 2.0)
        fig, ax = plt.subplots(figsize=(max(7, len(rows) * 0.8 + 2), height), dpi=110)

        b1 = ax.bar(
            [i - width / 2 for i in x], inicios, width,
            label="Inicio", color="#2E75B6",
        )
        b2 = ax.bar(
            [i + width / 2 for i in x], actuales, width,
            label="Actual", color="#C00000",
        )

        for bar, val in list(zip(b1, inicios)) + list(zip(b2, actuales)):
            if val > 0:
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.3,
                    str(val), ha="center", va="bottom", fontsize=7,
                )

        ax.set_xticks(list(x))
        ax.set_xticklabels(names, rotation=35, ha="right", fontsize=8)
        ax.set_title(title, fontsize=11, fontweight="bold", color="#1F3864")
        ax.legend(fontsize=9, frameon=False)
        ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        fig.tight_layout()
        buf = io.BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight")
        plt.close(fig)
        buf.seek(0)
        return buf

    def quarterly_progress_bars(
        self, progress: QuarterlyProgressData | None, title: str
    ) -> io.BytesIO:
        """T-D049: gráfico de barras con las 6 métricas de avance por Q."""
        if progress is None:
            return self._empty_chart(title)

        labels = ["Entraron", "Resueltas", "Pospuestas", "No cumplidas", "En curso", "Descartadas"]
        values = [
            progress.entraron, progress.resueltas, progress.pospuestas,
            progress.no_cumplidas, progress.en_curso, progress.descartadas,
        ]
        colors = ["#1F3864", "#70AD47", "#FF9900", "#C00000", "#2E75B6", "#D9D9D9"]

        fig, ax = plt.subplots(figsize=(6, 3.5), dpi=110)
        bars = ax.bar(labels, values, color=colors)
        for bar, val in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1, str(val),
                ha="center", va="bottom", fontsize=8,
            )
        ax.set_title(title, fontsize=11, fontweight="bold", color="#1F3864")
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=20, ha="right", fontsize=8)
        ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        fig.tight_layout()
        buf = io.BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight")
        plt.close(fig)
        buf.seek(0)
        return buf

    def _empty_chart(self, title: str) -> io.BytesIO:
        fig, ax = plt.subplots(figsize=(5, 3), dpi=110)
        ax.text(0.5, 0.5, "Sin datos", ha="center", va="center",
                transform=ax.transAxes, fontsize=12)
        ax.axis("off")
        ax.set_title(title, fontsize=11, fontweight="bold", color="#1F3864")
        buf = io.BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight")
        plt.close(fig)
        buf.seek(0)
        return buf
