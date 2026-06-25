from __future__ import annotations

from pydantic import BaseModel


class ConfigOut(BaseModel):
    dt_base_url: str
    sync_interval_hours: int
    kev_stale_days: int
    w_cvss_weight: float
    w_epss_weight: float
    w_kev_weight: float
    kev_minimum_score: float
    epss_high_threshold: float
    cvss_high_threshold: float


class UpdateConfigRequest(BaseModel):
    sync_interval_hours: int | None = None
    kev_stale_days: int | None = None
    w_cvss_weight: float | None = None
    w_epss_weight: float | None = None
    w_kev_weight: float | None = None
    kev_minimum_score: float | None = None
    epss_high_threshold: float | None = None
    cvss_high_threshold: float | None = None


class TestConnectionOut(BaseModel):
    ok: bool
    dt_version: str | None = None
    error: str | None = None
