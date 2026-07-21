def parse_cvss_v3_base_score(vector: str | None) -> float | None:
    """Calcula el base score CVSS 3.x a partir del string de vector.

    Retorna None si el vector está ausente, mal formado o no es v3.x.
    Ejemplo: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N' → 5.5
    """
    if not vector:
        return None
    try:
        from cvss import CVSS3

        c = CVSS3(vector)
        return float(c.base_score)
    except Exception:
        return None
