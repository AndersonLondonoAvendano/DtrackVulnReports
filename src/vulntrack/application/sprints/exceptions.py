"""Excepciones compartidas entre los casos de uso de sprints."""
from __future__ import annotations

from vulntrack.domain.exceptions import DomainError


class SprintNotFoundError(DomainError):
    def __init__(self, sprint_id: int) -> None:
        super().__init__(f"Sprint {sprint_id} no encontrado")
        self.sprint_id = sprint_id


class SprintAlreadyClosedError(DomainError):
    def __init__(self, sprint_id: int) -> None:
        super().__init__(f"El sprint {sprint_id} ya está cerrado")
        self.sprint_id = sprint_id
