from dataclasses import dataclass
from datetime import datetime


@dataclass
class Project:
    uuid: str
    name: str
    version: str | None
    description: str | None
    last_bom_import: datetime | None
    last_synced_at: datetime
