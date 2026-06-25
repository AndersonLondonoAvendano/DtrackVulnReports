from dataclasses import dataclass
from datetime import date


@dataclass
class KevEntry:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: date
    short_description: str
    required_action: str
    due_date: date | None
    notes: str | None
