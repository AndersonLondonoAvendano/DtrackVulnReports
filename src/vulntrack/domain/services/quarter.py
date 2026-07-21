from datetime import date


def quarter_of(d: date) -> tuple[int, int]:
    """Trimestre calendario estándar: Q1 ene-mar, Q2 abr-jun, Q3 jul-sep, Q4 oct-dic.

    Retorna (anio, trimestre).
    """
    return d.year, (d.month - 1) // 3 + 1
