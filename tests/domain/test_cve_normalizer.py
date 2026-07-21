from vulntrack.domain.services.cve_normalizer import extract_cve


class TestExtractCve:
    def test_vuln_id_is_cve(self) -> None:
        assert extract_cve("CVE-2024-1234", "NVD", []) == "CVE-2024-1234"

    def test_vuln_id_cve_uppercased(self) -> None:
        assert extract_cve("cve-2024-1234", "NVD", []) == "CVE-2024-1234"

    def test_ghsa_with_cve_alias(self) -> None:
        aliases = [{"cveId": "CVE-2018-1002204", "ghsaId": "GHSA-3v6h-hqm4-2rg6"}]
        result = extract_cve("GHSA-3v6h-hqm4-2rg6", "GITHUB", aliases)
        assert result == "CVE-2018-1002204"

    def test_ghsa_without_cve_alias_returns_none(self) -> None:
        assert extract_cve("GHSA-xxxx-xxxx-xxxx", "GITHUB", []) is None

    def test_alias_without_cve_key_returns_none(self) -> None:
        aliases = [{"ghsaId": "GHSA-xxxx-xxxx-xxxx"}]
        assert extract_cve("GHSA-xxxx-xxxx-xxxx", "GITHUB", aliases) is None

    def test_multiple_aliases_first_cve_wins(self) -> None:
        aliases = [
            {"ghsaId": "GHSA-xxxx"},
            {"cveId": "CVE-2021-4264", "ghsaId": "GHSA-c6rp-wrp9-qr4q"},
        ]
        result = extract_cve("GHSA-c6rp-wrp9-qr4q", "GITHUB", aliases)
        assert result == "CVE-2021-4264"

    def test_alias_cve_key_uppercased(self) -> None:
        aliases = [{"cveId": "cve-2024-45590"}]
        result = extract_cve("GHSA-xxxx", "GITHUB", aliases)
        assert result == "CVE-2024-45590"
