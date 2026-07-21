from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel

from vulntrack.interfaces.web.schemas.treatment import TreatmentSummaryOut


class ProjectOut(BaseModel):
    uuid: str
    name: str
    version: str | None
    description: str | None
    last_synced_at: datetime | None


class SnapshotOut(BaseModel):
    snapshot_date: date
    critical: int
    high: int
    medium: int
    low: int
    unassigned: int
    total: int
    risk_score: float


class PrioritizedFindingOut(BaseModel):
    finding_id: int
    vuln_id: str
    project_uuid: str
    project_name: str
    component_name: str
    component_version: str | None
    severity: str
    cvss_v3_base_score: float | None
    epss_score: float | None
    is_kev: bool
    priority_score: float
    priority_band: str
    treatment: TreatmentSummaryOut | None = None


class ProjectDetailOut(BaseModel):
    project: ProjectOut
    current_snapshot: SnapshotOut | None
    prioritized_findings: list[PrioritizedFindingOut]
    open_tasks_count: int


class ProjectListOut(BaseModel):
    items: list[ProjectOut]
    total: int
