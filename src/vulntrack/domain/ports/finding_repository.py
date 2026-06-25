from datetime import date
from typing import Protocol

from vulntrack.domain.entities.finding import Finding


class FindingRepository(Protocol):
    async def upsert_batch(self, findings: list[Finding]) -> None: ...

    async def list_by_project(
        self, project_uuid: str, suppress_suppressed: bool = True
    ) -> list[Finding]: ...

    async def list_all_active(self) -> list[Finding]: ...

    async def get_new_in_range(
        self, date_from: date, date_to: date
    ) -> list[Finding]: ...
