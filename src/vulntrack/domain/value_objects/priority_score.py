from dataclasses import dataclass
from enum import StrEnum


class PriorityBand(StrEnum):
    CRITICAL = "CRITICAL"  # 75-100
    HIGH = "HIGH"          # 50-74
    MEDIUM = "MEDIUM"      # 25-49
    LOW = "LOW"            # 0-24

    @classmethod
    def from_value(cls, value: float) -> "PriorityBand":
        if value >= 75.0:
            return cls.CRITICAL
        if value >= 50.0:
            return cls.HIGH
        if value >= 25.0:
            return cls.MEDIUM
        return cls.LOW


@dataclass(frozen=True)
class PriorityScore:
    value: float  # 0-100
    band: PriorityBand
    is_kev: bool
    breakdown: dict[str, float]

    def __post_init__(self) -> None:
        if not (0.0 <= self.value <= 100.0):
            raise ValueError(f"PriorityScore.value must be in [0, 100], got {self.value}")
