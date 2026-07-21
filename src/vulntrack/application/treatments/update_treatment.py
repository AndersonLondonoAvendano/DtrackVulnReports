"""T-D022: caso de uso UpdateTreatment -- valida transición de estado
(iter3-design.md §4.2), exige motivo para POSPUESTA/DESCARTADA y gestiona
fecha_cierre en estados terminales."""
from __future__ import annotations

from datetime import UTC, date, datetime

from vulntrack.domain.entities.vulnerability_treatment import (
    TratamientoVulnerabilidad,
    TreatmentStatus,
    requires_reason,
)
from vulntrack.domain.exceptions import DomainError
from vulntrack.domain.ports.treatment_repository import TreatmentRepository
from vulntrack.domain.services.treatment_transitions import validate_transition

_TERMINAL_STATES = (TreatmentStatus.FINALIZADA, TreatmentStatus.DESCARTADA)


class TreatmentNotFoundError(DomainError):
    def __init__(self, treatment_id: int) -> None:
        super().__init__(f"Tratamiento {treatment_id} no encontrado")
        self.treatment_id = treatment_id


class MissingReasonError(DomainError):
    def __init__(self, status: TreatmentStatus) -> None:
        super().__init__(f"Se requiere un motivo para pasar a {status}")
        self.status = status


class UpdateTreatmentUseCase:
    def __init__(self, repo: TreatmentRepository) -> None:
        self._repo = repo

    async def execute(
        self,
        treatment_id: int,
        *,
        estado: TreatmentStatus | None = None,
        sprint_id: int | None = None,
        responsable: str | None = None,
        fecha_objetivo: date | None = None,
        notas: str | None = None,
        motivo: str | None = None,
    ) -> TratamientoVulnerabilidad:
        treatment = await self._repo.get_by_id(treatment_id)
        if treatment is None:
            raise TreatmentNotFoundError(treatment_id)

        fields: dict[str, object] = {}
        changes_status = estado is not None and estado != treatment.estado

        if changes_status:
            assert estado is not None
            validate_transition(treatment.estado, estado, actor="user")
            if requires_reason(estado) and not motivo:
                raise MissingReasonError(estado)
            fields["estado"] = estado
            fields["fecha_cierre"] = datetime.now(UTC) if estado in _TERMINAL_STATES else None

        if sprint_id is not None:
            fields["sprint_id"] = sprint_id
        if responsable is not None:
            fields["responsable"] = responsable
        if fecha_objetivo is not None:
            fields["fecha_objetivo"] = fecha_objetivo
        if notas is not None:
            fields["notas"] = notas
        if motivo is not None:
            fields["motivo"] = motivo

        updated = await self._repo.update(treatment_id, **fields)

        if changes_status and estado is not None:
            await self._repo.append_history(
                treatment_id,
                from_status=treatment.estado,
                to_status=estado,
                sprint_id=sprint_id if sprint_id is not None else treatment.sprint_id,
                note=motivo,
            )

        return updated
