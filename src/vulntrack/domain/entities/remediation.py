from dataclasses import dataclass
from datetime import date, datetime
from enum import StrEnum

from vulntrack.domain.value_objects.priority_score import PriorityBand


class TaskStatus(StrEnum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    DISCARDED = "DISCARDED"


@dataclass
class RemediationPlan:
    id: int
    project_uuid: str
    name: str
    description: str | None
    created_at: datetime
    updated_at: datetime


@dataclass
class RemediationTask:
    id: int
    plan_id: int
    finding_id: int | None
    title: str
    description: str | None
    assignee: str | None
    status: TaskStatus
    priority_band: PriorityBand
    recommended_action: str | None
    target_date: date | None
    completed_at: datetime | None
    notes: str | None
    created_at: datetime
    updated_at: datetime

    def is_overdue(self, today: date) -> bool:
        if self.target_date is None:
            return False
        if self.status in (TaskStatus.COMPLETED, TaskStatus.DISCARDED):
            return False
        return today > self.target_date
