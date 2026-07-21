from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from vulntrack.domain.value_objects.severity import Severity


class FindingLifecycleState(StrEnum):
    ACTIVA = "ACTIVA"
    RESUELTA = "RESUELTA"


@dataclass
class Finding:
    id: int
    project_uuid: str
    dt_finding_uuid: str
    component_name: str
    component_version: str | None
    component_group: str | None
    vuln_id: str
    vuln_source: str
    severity: Severity
    cvss_v3_base_score: float | None
    epss_score: float | None
    epss_percentile: float | None
    attributed_on: datetime | None
    suppressed: bool
    last_synced_at: datetime
    cve_id: str | None = None
    estado_ciclo_vida: FindingLifecycleState = FindingLifecycleState.ACTIVA
    primera_deteccion_at: datetime | None = None
    ultima_vista_at: datetime | None = None
    resuelta_at: datetime | None = None
    es_reincidente: bool = False
    reaparicion_count: int = 0
    ultima_reaparicion_at: datetime | None = None

    @property
    def display_id(self) -> str:
        """CVE si existe, GHSA/vulnId si no."""
        return self.cve_id or self.vuln_id

    def normalized_cvss(self) -> float:
        return (self.cvss_v3_base_score or 0.0) / 10.0

    def safe_epss(self) -> float:
        return self.epss_score or 0.0
