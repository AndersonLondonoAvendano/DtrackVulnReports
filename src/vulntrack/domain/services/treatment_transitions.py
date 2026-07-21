"""T-D002/T-D008: máquina de estados y estados activos de tratamiento (D2/D3).

`ACTIVE_TREATMENT_STATES` es la fuente única de verdad para D2 (anti-
duplicación): la usan tanto el índice único parcial de la migración/ORM
como la consulta de "disponibles" -- un tratamiento en uno de estos estados
cuenta como "tomado" y bloquea que la misma vulnerabilidad
(project_uuid + vuln_key) se ofrezca de nuevo o se cree un tratamiento
duplicado.

Corrección post-FASE1 (descubierta probando el flujo real end-to-end):
PENDIENTE también cuenta como "tomado". El encargo dice explícitamente que,
apenas el equipo le asigna sprint + estado a una vulnerabilidad, "a partir
de ahí queda tomada" -- eso ocurre en el momento de creación (PENDIENTE),
no sólo cuando alguien empieza a trabajarla (EN_CURSO). El único estado que
libera la vulnerabilidad de vuelta al pool de "disponibles" es NO_CUMPLIDA
(cerró el sprint sin resolver, iter3-design.md §4.5).

`validate_transition` codifica la tabla de `iter3-design.md §4.2`. Distingue
entre transiciones que un usuario puede disparar manualmente (API/UI) y
transiciones que sólo el sistema dispara automáticamente: cierre de sprint
(-> NO_CUMPLIDA, §4.5) y reincidencia (FINALIZADA -> EN_CURSO, D3, §4.4).
"""
from __future__ import annotations

from typing import Literal

from vulntrack.domain.entities.vulnerability_treatment import TreatmentStatus
from vulntrack.domain.exceptions import DomainError

ACTIVE_TREATMENT_STATES: frozenset[str] = frozenset(
    {"PENDIENTE", "EN_CURSO", "FINALIZADA", "POSPUESTA", "DESCARTADA"}
)

Actor = Literal["user", "system"]


class InvalidTreatmentTransitionError(DomainError):
    def __init__(self, from_status: TreatmentStatus, to_status: TreatmentStatus) -> None:
        super().__init__(f"Transición inválida: {from_status} → {to_status}")
        self.from_status = from_status
        self.to_status = to_status


# Transiciones que un usuario puede disparar manualmente vía API/UI.
_USER_TRANSITIONS: dict[TreatmentStatus, frozenset[TreatmentStatus]] = {
    TreatmentStatus.PENDIENTE: frozenset(
        {TreatmentStatus.EN_CURSO, TreatmentStatus.POSPUESTA, TreatmentStatus.DESCARTADA}
    ),
    TreatmentStatus.EN_CURSO: frozenset(
        {TreatmentStatus.FINALIZADA, TreatmentStatus.POSPUESTA, TreatmentStatus.DESCARTADA}
    ),
    TreatmentStatus.FINALIZADA: frozenset(),
    TreatmentStatus.POSPUESTA: frozenset(
        {TreatmentStatus.EN_CURSO, TreatmentStatus.DESCARTADA}
    ),
    TreatmentStatus.NO_CUMPLIDA: frozenset(
        {TreatmentStatus.EN_CURSO, TreatmentStatus.POSPUESTA, TreatmentStatus.DESCARTADA}
    ),
    TreatmentStatus.DESCARTADA: frozenset(),
}

# Transiciones que sólo el sistema dispara automáticamente -- nunca vía
# acción manual de un usuario.
_SYSTEM_ONLY_TRANSITIONS: dict[TreatmentStatus, frozenset[TreatmentStatus]] = {
    TreatmentStatus.PENDIENTE: frozenset({TreatmentStatus.NO_CUMPLIDA}),
    TreatmentStatus.EN_CURSO: frozenset({TreatmentStatus.NO_CUMPLIDA}),
    TreatmentStatus.FINALIZADA: frozenset({TreatmentStatus.EN_CURSO}),
    TreatmentStatus.POSPUESTA: frozenset({TreatmentStatus.NO_CUMPLIDA}),
    TreatmentStatus.NO_CUMPLIDA: frozenset(),
    TreatmentStatus.DESCARTADA: frozenset(),
}


def validate_transition(
    from_status: TreatmentStatus, to_status: TreatmentStatus, *, actor: Actor
) -> None:
    """Lanza `InvalidTreatmentTransitionError` si la transición no está permitida.

    Una transición hacia el mismo estado (p. ej. POSPUESTA -> POSPUESTA al
    reposponer a otro sprint) siempre es válida: no cambia de estado, sólo
    de metadatos (sprint, fecha, motivo).
    """
    if from_status == to_status:
        return
    allowed = set(_USER_TRANSITIONS.get(from_status, frozenset()))
    if actor == "system":
        allowed |= _SYSTEM_ONLY_TRANSITIONS.get(from_status, frozenset())
    if to_status not in allowed:
        raise InvalidTreatmentTransitionError(from_status, to_status)
