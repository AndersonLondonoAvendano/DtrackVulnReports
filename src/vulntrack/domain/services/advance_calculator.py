from dataclasses import dataclass, field

from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.metric_snapshot import MetricSnapshot
from vulntrack.domain.entities.project import Project
from vulntrack.domain.exceptions import SnapshotNotAvailableError
from vulntrack.domain.value_objects.severity import Severity


@dataclass
class AdvanceResult:
    project_uuid: str
    inicio: MetricSnapshot | None
    actual: MetricSnapshot | None
    variacion_total: int
    tratadas: int
    nuevas_por_severidad: dict[Severity, int] = field(default_factory=dict)


class AdvanceCalculator:
    def calculate(
        self,
        project: Project,
        inicio_snapshot: MetricSnapshot | None,
        actual_snapshot: MetricSnapshot | None,
        new_findings: list[Finding],
    ) -> AdvanceResult:
        if inicio_snapshot is None:
            raise SnapshotNotAvailableError(
                project.uuid, "inicio snapshot required for advance calculation"
            )

        inicio_total = inicio_snapshot.total_assigned()
        actual_total = actual_snapshot.total_assigned() if actual_snapshot is not None else 0

        variacion_total = actual_total - inicio_total
        tratadas = max(0, -variacion_total)

        nuevas_por_severidad: dict[Severity, int] = dict.fromkeys(Severity, 0)
        for f in new_findings:
            if f.severity in nuevas_por_severidad:
                nuevas_por_severidad[f.severity] += 1

        return AdvanceResult(
            project_uuid=project.uuid,
            inicio=inicio_snapshot,
            actual=actual_snapshot,
            variacion_total=variacion_total,
            tratadas=tratadas,
            nuevas_por_severidad=nuevas_por_severidad,
        )
