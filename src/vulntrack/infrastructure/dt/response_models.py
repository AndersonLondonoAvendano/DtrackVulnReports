"""Modelos Pydantic que mapean la respuesta JSON de la API REST de Dependency-Track v4.x."""
from __future__ import annotations

from datetime import datetime

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DtProject(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    uuid: str
    name: str
    version: str | None = None
    description: str | None = None
    last_bom_import: datetime | None = Field(None, alias="lastBomImport")


class DtMetrics(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unassigned: int = 0
    risk_score: float = Field(0.0, alias="inheritedRiskScore")
    total: int = Field(0, alias="vulnerabilities")
    first_occurrence: datetime | None = Field(None, alias="firstOccurrence")
    last_occurrence: datetime | None = Field(None, alias="lastOccurrence")


class DtComponent(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    uuid: str | None = None
    name: str
    version: str | None = None
    group: str | None = None
    purl: str | None = None


class DtVulnerabilityAnalysis(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    state: str | None = None
    justification: str | None = None
    response: list[str] = Field(default_factory=list)
    detail: str | None = None
    suppressed: bool = Field(False, alias="isSuppressed")


class DtVulnerabilityInFinding(BaseModel):
    """Objeto vulnerability anidado dentro de un Finding de DT."""

    model_config = ConfigDict(populate_by_name=True)

    uuid: str | None = None
    vuln_id: str = Field(..., alias="vulnId")
    source: str = ""
    aliases: list[dict[str, str]] = Field(default_factory=list)
    title: str | None = None
    severity: str = "UNASSIGNED"
    cvss_v3_base_score: float | None = Field(None, alias="cvssV3BaseScore")
    cvss_v3_vector: str | None = Field(None, alias="cvssV3Vector")
    epss_score: float | None = Field(None, alias="epssScore")
    epss_percentile: float | None = Field(None, alias="epssPercentile")
    cwes: list[int] = Field(default_factory=list)

    @field_validator("cwes", mode="before")
    @classmethod
    def parse_cwes(cls, v: Any) -> list[int]:
        # DT v4.11+ devuelve cwes como lista de objetos {"cweId": 20, "name": "..."}
        # versiones anteriores lo devuelven como lista de enteros
        result: list[int] = []
        for item in v or []:
            if isinstance(item, int):
                result.append(item)
            elif isinstance(item, dict):
                cwe_id = item.get("cweId") or item.get("cwe")
                if isinstance(cwe_id, int):
                    result.append(cwe_id)
        return result


class DtFinding(BaseModel):
    """Elemento de la lista devuelta por GET /api/v1/finding/project/{uuid}."""

    model_config = ConfigDict(populate_by_name=True)

    component: DtComponent
    vulnerability: DtVulnerabilityInFinding
    analysis: DtVulnerabilityAnalysis | None = None
    attribution: DtAttribution | None = None
    matrix: str | None = None


class DtAttribution(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    uuid: str | None = None
    finding_uuid: str | None = Field(None, alias="findingUuid")
    alt_id: str | None = Field(None, alias="alternativeIdentifier")
    reference_url: str | None = Field(None, alias="referenceUrl")
    attributed_on: datetime | None = Field(None, alias="attributedOn")
    analyzerid: str | None = Field(None, alias="analyzerid")
    analyzeridentity: str | None = None


DtFinding.model_rebuild()


class DtMetricsHistory(BaseModel):
    """Elemento de GET /api/v1/metrics/project/{uuid}/days/{days}."""

    model_config = ConfigDict(populate_by_name=True)

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unassigned: int = 0
    risk_score: float = Field(0.0, alias="inheritedRiskScore")
    total: int = Field(0, alias="vulnerabilities")
    first_occurrence: datetime | None = Field(None, alias="firstOccurrence")
    last_occurrence: datetime | None = Field(None, alias="lastOccurrence")


class DtAbout(BaseModel):
    """Respuesta de GET /api/v1/about."""

    model_config = ConfigDict(populate_by_name=True)

    version: str = ""
    uuid: str | None = None
    application: str | None = None
    timestamp: str | None = None
