"""T-E006: identidad D1 -- único lugar de verdad para comparar identidad de
vulnerabilidad (iter4-design.md D1): (proyecto, CVE canónico o vuln_id si no
hay CVE, componente, versión). `component_version=None` se normaliza a "" para
que dos identidades con versión ausente comparen igual entre sí de forma
consistente (misma normalización que usa el índice `COALESCE(..., '')` de la
migración 0006).
"""
from __future__ import annotations


def identity_key(
    project_uuid: str,
    cve_id: str | None,
    vuln_id: str,
    component_name: str,
    component_version: str | None,
) -> tuple[str, str, str, str]:
    vuln_key = cve_id or vuln_id
    return (project_uuid, vuln_key, component_name, component_version or "")
