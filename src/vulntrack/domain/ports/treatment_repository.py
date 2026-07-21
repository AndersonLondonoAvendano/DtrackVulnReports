from datetime import date
from typing import Any, Literal, Protocol

from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.vulnerability_treatment import (
    TratamientoVulnerabilidad,
    TreatmentStatus,
    TreatmentStatusHistoryEntry,
)
from vulntrack.domain.value_objects.priority_score import PriorityBand


class TreatmentRepository(Protocol):
    async def create(
        self,
        *,
        project_uuid: str,
        vuln_key: str,
        cve_id: str | None,
        finding_id: int | None,
        plan_id: int | None,
        sprint_id: int,
        responsable: str | None,
        priority_band: PriorityBand,
        fecha_objetivo: date | None = None,
        component_name: str | None = None,
        component_version: str | None = None,
    ) -> TratamientoVulnerabilidad: ...

    async def get_by_id(self, treatment_id: int) -> TratamientoVulnerabilidad | None: ...

    async def update(self, treatment_id: int, **fields: Any) -> TratamientoVulnerabilidad: ...

    async def remove(self, treatment_id: int) -> Literal["deleted", "unlinked"]: ...

    async def list_available_for_project(self, project_uuid: str) -> list[Finding]: ...

    async def list_by_project(
        self,
        project_uuid: str,
        *,
        sprint_id: int | None = None,
        estado: TreatmentStatus | None = None,
    ) -> list[TratamientoVulnerabilidad]: ...

    async def list_by_sprint(self, sprint_id: int) -> list[TratamientoVulnerabilidad]: ...

    async def list_all(
        self,
        *,
        sprint_id: int | None = None,
        estado: TreatmentStatus | None = None,
    ) -> list[TratamientoVulnerabilidad]: ...

    async def append_history(
        self,
        treatment_id: int,
        *,
        from_status: TreatmentStatus | None,
        to_status: TreatmentStatus,
        sprint_id: int,
        note: str | None = None,
    ) -> TreatmentStatusHistoryEntry: ...

    async def list_history(
        self, treatment_ids: list[int] | None = None
    ) -> list[TreatmentStatusHistoryEntry]: ...
