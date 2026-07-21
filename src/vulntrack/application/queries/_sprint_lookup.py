"""T-D037: resolución de nombre de sprint sin N+1 (Priorización enriquecida)."""
from __future__ import annotations

from vulntrack.domain.ports.sprint_repository import SprintRepository


async def build_sprint_name_map(sprint_repo: SprintRepository) -> dict[int, str]:
    sprints = await sprint_repo.list_all()
    return {s.id: s.nombre for s in sprints}
