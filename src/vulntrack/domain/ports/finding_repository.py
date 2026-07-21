from datetime import date, datetime
from typing import Protocol

from vulntrack.domain.entities.finding import Finding, FindingLifecycleState


class FindingRepository(Protocol):
    async def upsert_batch(self, findings: list[Finding]) -> None: ...

    async def list_by_project(
        self, project_uuid: str, suppress_suppressed: bool = True
    ) -> list[Finding]: ...

    async def list_all_active(self) -> list[Finding]: ...

    async def get_new_in_range(
        self, date_from: date, date_to: date
    ) -> list[Finding]: ...

    async def list_by_lifecycle_state(
        self, project_uuid: str, estado: FindingLifecycleState
    ) -> list[Finding]: ...

    async def list_resolved_in_range(
        self, date_from: date, date_to: date, project_uuid: str | None = None
    ) -> list[Finding]: ...

    async def mark_resolved(self, finding_id: int, resuelta_at: datetime) -> Finding: ...

    async def mark_reactivated(self, finding_id: int, reaparicion_at: datetime) -> Finding: ...
