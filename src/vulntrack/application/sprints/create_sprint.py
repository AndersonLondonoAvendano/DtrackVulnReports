"""T-D018: caso de uso CreateSprint (manual -- D1)."""
from __future__ import annotations

from datetime import date

from vulntrack.domain.entities.sprint import Sprint
from vulntrack.domain.exceptions import DomainError
from vulntrack.domain.ports.sprint_repository import SprintRepository
from vulntrack.domain.services.quarter import quarter_of


class CreateSprintUseCase:
    def __init__(self, repo: SprintRepository) -> None:
        self._repo = repo

    async def execute(
        self,
        *,
        nombre: str,
        fecha_inicio: date,
        fecha_fin: date,
        anio: int | None = None,
        trimestre: int | None = None,
        origen: str = "MANUAL",
        external_id: str | None = None,
    ) -> Sprint:
        if fecha_fin <= fecha_inicio:
            raise DomainError(
                "La fecha de fin del sprint debe ser posterior a la fecha de inicio"
            )

        if anio is None or trimestre is None:
            anio, trimestre = quarter_of(fecha_inicio)

        return await self._repo.create(
            nombre=nombre,
            anio=anio,
            trimestre=trimestre,
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
            origen=origen,
            external_id=external_id,
        )
