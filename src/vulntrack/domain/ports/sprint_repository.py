from datetime import date
from typing import Any, Protocol

from vulntrack.domain.entities.sprint import Sprint


class SprintRepository(Protocol):
    async def create(
        self,
        *,
        nombre: str,
        anio: int,
        trimestre: int,
        fecha_inicio: date,
        fecha_fin: date,
        origen: str = "MANUAL",
        external_id: str | None = None,
    ) -> Sprint: ...

    async def get_by_id(self, sprint_id: int) -> Sprint | None: ...

    async def list_all(
        self,
        *,
        anio: int | None = None,
        trimestre: int | None = None,
        estado: str | None = None,
    ) -> list[Sprint]: ...

    async def close(self, sprint_id: int) -> Sprint: ...

    async def update(self, sprint_id: int, **fields: Any) -> Sprint: ...
