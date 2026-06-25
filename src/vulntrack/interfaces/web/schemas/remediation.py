from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel


class CreatePlanRequest(BaseModel):
    name: str
    description: str | None = None


class PlanOut(BaseModel):
    id: int
    project_uuid: str
    name: str
    description: str | None
    created_at: datetime
    updated_at: datetime


class UpdateTaskRequest(BaseModel):
    status: str | None = None
    assignee: str | None = None
    notes: str | None = None
    target_date: date | None = None


class TaskOut(BaseModel):
    id: int
    plan_id: int
    finding_id: int | None
    title: str
    description: str | None
    assignee: str | None
    status: str
    priority_band: str
    recommended_action: str | None
    target_date: date | None
    completed_at: datetime | None
    notes: str | None
    created_at: datetime


class PlanDetailOut(BaseModel):
    plan: PlanOut
    tasks: list[TaskOut]
