from dataclasses import dataclass
from datetime import date, datetime
from enum import StrEnum


class SprintStatus(StrEnum):
    PLANEADO = "PLANEADO"
    ACTIVO = "ACTIVO"
    CERRADO = "CERRADO"


@dataclass
class Sprint:
    id: int
    nombre: str
    anio: int
    trimestre: int
    fecha_inicio: date
    fecha_fin: date
    estado: SprintStatus
    origen: str
    created_at: datetime
    updated_at: datetime
    external_id: str | None = None

    @property
    def q_label(self) -> str:
        return f"{self.anio}-Q{self.trimestre}"
