"""T-D019: caso de uso CloseSprint -- cierra un sprint y transiciona en bloque
los tratamientos que quedaron sin resolver a NO_CUMPLIDA (iter3-design.md §4.5)."""
from __future__ import annotations

from datetime import UTC, datetime

from vulntrack.application.sprints.exceptions import (
    SprintAlreadyClosedError,
    SprintNotFoundError,
)
from vulntrack.domain.entities.sprint import Sprint, SprintStatus
from vulntrack.domain.entities.vulnerability_treatment import TreatmentStatus
from vulntrack.domain.ports.sprint_repository import SprintRepository
from vulntrack.domain.ports.treatment_repository import TreatmentRepository
from vulntrack.domain.services.treatment_transitions import validate_transition

_UNRESOLVED_STATES = (TreatmentStatus.PENDIENTE, TreatmentStatus.EN_CURSO)


class CloseSprintUseCase:
    def __init__(
        self, sprint_repo: SprintRepository, treatment_repo: TreatmentRepository
    ) -> None:
        self._sprint_repo = sprint_repo
        self._treatment_repo = treatment_repo

    async def execute(self, sprint_id: int) -> Sprint:
        sprint = await self._sprint_repo.get_by_id(sprint_id)
        if sprint is None:
            raise SprintNotFoundError(sprint_id)
        if sprint.estado == SprintStatus.CERRADO:
            raise SprintAlreadyClosedError(sprint_id)

        sprint = await self._sprint_repo.close(sprint_id)

        now = datetime.now(UTC)
        for treatment in await self._treatment_repo.list_by_sprint(sprint_id):
            if treatment.estado not in _UNRESOLVED_STATES:
                continue
            validate_transition(treatment.estado, TreatmentStatus.NO_CUMPLIDA, actor="system")
            await self._treatment_repo.update(
                treatment.id,
                estado=TreatmentStatus.NO_CUMPLIDA,
                fecha_cierre=now,
            )
            await self._treatment_repo.append_history(
                treatment.id,
                from_status=treatment.estado,
                to_status=TreatmentStatus.NO_CUMPLIDA,
                sprint_id=sprint_id,
                note="Sprint cerrado sin resolver",
            )

        return sprint
