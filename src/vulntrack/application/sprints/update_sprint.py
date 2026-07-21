"""Caso de uso UpdateSprint -- edición de nombre/fechas (PATCH /api/v1/sprints/{id}).

No estaba en el desglose original del Grupo D3 (sólo Create/Close); se agrega
en D6 porque el router de sprints (T-D034) expone PATCH para editar, y la
validación de fechas debe vivir en la capa de aplicación, no en el router.
"""
from __future__ import annotations

from datetime import date

from vulntrack.application.sprints.exceptions import SprintNotFoundError
from vulntrack.domain.entities.sprint import Sprint
from vulntrack.domain.exceptions import DomainError
from vulntrack.domain.ports.sprint_repository import SprintRepository


class UpdateSprintUseCase:
    def __init__(self, repo: SprintRepository) -> None:
        self._repo = repo

    async def execute(
        self,
        sprint_id: int,
        *,
        nombre: str | None = None,
        fecha_inicio: date | None = None,
        fecha_fin: date | None = None,
        external_id: str | None = None,
    ) -> Sprint:
        sprint = await self._repo.get_by_id(sprint_id)
        if sprint is None:
            raise SprintNotFoundError(sprint_id)

        effective_inicio = fecha_inicio or sprint.fecha_inicio
        effective_fin = fecha_fin or sprint.fecha_fin
        if effective_fin <= effective_inicio:
            raise DomainError(
                "La fecha de fin del sprint debe ser posterior a la fecha de inicio"
            )

        fields: dict[str, object] = {}
        if nombre is not None:
            fields["nombre"] = nombre
        if fecha_inicio is not None:
            fields["fecha_inicio"] = fecha_inicio
        if fecha_fin is not None:
            fields["fecha_fin"] = fecha_fin
        if external_id is not None:
            fields["external_id"] = external_id

        return await self._repo.update(sprint_id, **fields)
