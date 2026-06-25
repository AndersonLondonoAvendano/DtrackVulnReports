from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel


class KevStatusOut(BaseModel):
    entries_count: int
    catalog_date: date | None
    last_updated: datetime | None
    is_stale: bool
    stale_threshold_days: int


class KevFindingOut(BaseModel):
    vuln_id: str
    component_name: str
    component_version: str | None
    project_name: str
    severity: str
    date_added: date | None
    required_action: str | None


class KevRefreshOut(BaseModel):
    status: str
    message: str
