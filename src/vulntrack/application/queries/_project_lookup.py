"""T-D026: resolución de nombre de proyecto sin N+1 (F1)."""
from __future__ import annotations

from vulntrack.domain.ports.project_repository import ProjectRepository


async def build_project_name_map(project_repo: ProjectRepository) -> dict[str, str]:
    """Una sola consulta a `projects`, reutilizable por cualquier listado que
    necesite mostrar el nombre en vez del UUID."""
    projects = await project_repo.list_all()
    return {p.uuid: p.name for p in projects}
