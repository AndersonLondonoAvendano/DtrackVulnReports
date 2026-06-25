import time
from datetime import date

from vulntrack.domain.entities.kev_entry import KevEntry
from vulntrack.domain.services.kev_matcher import KevMatcher


def make_kev(cve_id: str) -> KevEntry:
    return KevEntry(
        cve_id=cve_id,
        vendor_project="Vendor",
        product="Product",
        vulnerability_name="Vuln",
        date_added=date(2024, 1, 1),
        short_description="Description",
        required_action="Patch",
        due_date=None,
        notes=None,
    )


class TestKevMatcher:
    def setup_method(self) -> None:
        self.entries = [make_kev("CVE-2021-44228"), make_kev("CVE-2022-22965")]
        self.matcher = KevMatcher(self.entries)

    def test_known_cve_found(self) -> None:
        assert self.matcher.is_in_kev("CVE-2021-44228") is True

    def test_unknown_cve_not_found(self) -> None:
        assert self.matcher.is_in_kev("CVE-9999-99999") is False

    def test_case_insensitive_lookup(self) -> None:
        assert self.matcher.is_in_kev("cve-2021-44228") is True
        assert self.matcher.is_in_kev("Cve-2021-44228") is True

    def test_get_kev_details_found(self) -> None:
        entry = self.matcher.get_kev_details("CVE-2021-44228")
        assert entry is not None
        assert entry.cve_id == "CVE-2021-44228"

    def test_get_kev_details_not_found(self) -> None:
        assert self.matcher.get_kev_details("CVE-0000-00000") is None

    def test_get_kev_details_case_insensitive(self) -> None:
        entry = self.matcher.get_kev_details("cve-2022-22965")
        assert entry is not None

    def test_large_catalog_performance(self) -> None:
        large_entries = [make_kev(f"CVE-2024-{i:05d}") for i in range(1000)]
        matcher = KevMatcher(large_entries)
        start = time.perf_counter()
        for i in range(1000):
            matcher.is_in_kev(f"CVE-2024-{i:05d}")
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 10.0, f"1000 lookups took {elapsed_ms:.2f}ms (expected <10ms)"

    def test_empty_catalog(self) -> None:
        matcher = KevMatcher([])
        assert matcher.is_in_kev("CVE-2021-44228") is False
        assert matcher.get_kev_details("CVE-2021-44228") is None
