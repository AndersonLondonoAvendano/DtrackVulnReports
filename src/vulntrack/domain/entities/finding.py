from dataclasses import dataclass
from datetime import datetime

from vulntrack.domain.value_objects.severity import Severity


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

    def normalized_cvss(self) -> float:
        return (self.cvss_v3_base_score or 0.0) / 10.0

    def safe_epss(self) -> float:
        return self.epss_score or 0.0
