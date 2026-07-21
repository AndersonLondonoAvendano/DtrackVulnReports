import re

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


def extract_cve(vuln_id: str, source: str, aliases: list[dict[str, str]]) -> str | None:  # noqa: ARG001
    """Retorna el CVE canónico (uppercase) si existe, None en otro caso.

    Prioridad:
    1. Si vuln_id es un CVE válido, retorna vuln_id.upper().
    2. Busca en aliases el primer objeto con clave 'cveId' que sea CVE válido.
    3. Retorna None si no hay CVE (GHSA sin alias, etc.).
    """
    if _CVE_RE.match(vuln_id):
        return vuln_id.upper()
    for alias in aliases:
        cve = alias.get("cveId") or alias.get("cve")
        if cve and _CVE_RE.match(cve):
            return cve.upper()
    return None
