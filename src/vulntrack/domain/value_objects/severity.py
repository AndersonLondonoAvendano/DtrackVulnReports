from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNASSIGNED = "UNASSIGNED"

    def weight(self) -> float:
        weights = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.75,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.25,
            Severity.UNASSIGNED: 0.1,
        }
        return weights[self]

    def color_hex(self) -> str:
        colors = {
            Severity.CRITICAL: "#C00000",
            Severity.HIGH: "#FF0000",
            Severity.MEDIUM: "#FF9900",
            Severity.LOW: "#FFFF00",
            Severity.UNASSIGNED: "#D9D9D9",
        }
        return colors[self]
