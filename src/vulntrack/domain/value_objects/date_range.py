from dataclasses import dataclass
from datetime import date

from vulntrack.domain.exceptions import DomainError


@dataclass(frozen=True)
class DateRange:
    date_from: date
    date_to: date

    def __post_init__(self) -> None:
        if self.date_from > self.date_to:
            raise DomainError(
                f"date_from ({self.date_from}) must be <= date_to ({self.date_to})"
            )

    def days(self) -> int:
        return (self.date_to - self.date_from).days
