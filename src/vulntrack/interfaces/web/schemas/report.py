from __future__ import annotations

from datetime import date

from pydantic import BaseModel, model_validator


class GenerateReportRequest(BaseModel):
    period: str = "quarterly"  # quarterly | monthly | custom
    quarter: str | None = None  # Q1 | Q2 | Q3 | Q4
    year: int | None = None
    date_from: date | None = None
    date_to: date | None = None
    formats: list[str] = ["xlsx"]
    project_uuids: list[str] | None = None

    @model_validator(mode="after")
    def validate_period(self) -> "GenerateReportRequest":
        if self.period == "custom":
            if self.date_from is None or self.date_to is None:
                raise ValueError("date_from y date_to son requeridos para período custom")
        elif self.period in ("quarterly", "monthly"):
            if self.year is None:
                raise ValueError("year es requerido")
            if self.period == "quarterly" and self.quarter is None:
                raise ValueError("quarter es requerido para período quarterly")
        return self
