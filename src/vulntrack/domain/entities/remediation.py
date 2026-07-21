from dataclasses import dataclass
from datetime import datetime


@dataclass
class RemediationPlan:
    id: int
    project_uuid: str
    name: str
    description: str | None
    sprint_id: int | None
    created_at: datetime
    updated_at: datetime
