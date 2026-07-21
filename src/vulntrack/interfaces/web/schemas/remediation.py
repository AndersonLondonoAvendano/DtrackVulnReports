from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from vulntrack.interfaces.web.schemas.treatment import TreatmentOut


class CreatePlanRequest(BaseModel):
    name: str
    sprint_id: int
    description: str | None = None


class PlanOut(BaseModel):
    id: int
    project_uuid: str
    name: str
    description: str | None
    sprint_id: int | None
    created_at: datetime
    updated_at: datetime


class PlanDetailOut(BaseModel):
    plan: PlanOut
    treatments: list[TreatmentOut]
