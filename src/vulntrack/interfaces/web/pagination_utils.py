"""T-D030: lógica de numeración de páginas con elipsis (pura, sin dependencias web)."""
from __future__ import annotations


def build_page_range(current: int, total_pages: int) -> list[int | None]:
    """Retorna la secuencia de números de página a mostrar, con `None` como
    marcador de elipsis. Ej.: current=5, total_pages=43 -> [1, None, 4, 5, 6, None, 43]."""
    if total_pages <= 7:
        return list(range(1, total_pages + 1))

    candidates = {1, total_pages, current, current - 1, current + 1}
    pages = sorted(p for p in candidates if 1 <= p <= total_pages)

    result: list[int | None] = []
    previous: int | None = None
    for p in pages:
        if previous is not None and p - previous > 1:
            result.append(None)
        result.append(p)
        previous = p
    return result
