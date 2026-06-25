from vulntrack.domain.entities.kev_entry import KevEntry


class KevMatcher:
    def __init__(self, entries: list[KevEntry]) -> None:
        self._index: dict[str, KevEntry] = {
            e.cve_id.upper(): e for e in entries
        }

    def is_in_kev(self, vuln_id: str) -> bool:
        return vuln_id.upper() in self._index

    def get_kev_details(self, vuln_id: str) -> KevEntry | None:
        return self._index.get(vuln_id.upper())
