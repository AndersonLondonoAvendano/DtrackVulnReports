from dataclasses import dataclass
from datetime import date
from enum import StrEnum


class SnapshotSource(StrEnum):
    DT_CURRENT = "DT_CURRENT"
    DT_HISTORICAL = "DT_HISTORICAL"
    LOCAL = "LOCAL"


@dataclass
class MetricSnapshot:
    id: int
    project_uuid: str
    snapshot_date: date
    critical: int
    high: int
    medium: int
    low: int
    unassigned: int
    total: int
    risk_score: float
    source: SnapshotSource

    def total_assigned(self) -> int:
        return self.critical + self.high + self.medium + self.low
