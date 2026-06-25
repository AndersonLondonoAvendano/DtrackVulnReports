from datetime import date
from typing import Protocol

from vulntrack.domain.entities.metric_snapshot import MetricSnapshot


class SnapshotRepository(Protocol):
    async def upsert(self, snapshot: MetricSnapshot) -> None: ...

    async def get_closest_before(
        self, project_uuid: str, ref_date: date
    ) -> MetricSnapshot | None: ...

    async def get_closest_after(
        self, project_uuid: str, ref_date: date
    ) -> MetricSnapshot | None: ...

    async def list_by_project_in_range(
        self, project_uuid: str, date_from: date, date_to: date
    ) -> list[MetricSnapshot]: ...

    async def count_by_source(self, source: str) -> int: ...
