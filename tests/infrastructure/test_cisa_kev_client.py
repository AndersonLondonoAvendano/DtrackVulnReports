"""Tests del cliente CISA KEV (T-043)."""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import httpx
import pytest
import respx

from vulntrack.infrastructure.kev.cisa_kev_client import (
    CISA_KEV_URL,
    CisaKevClient,
    KevFetchError,
)

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE_JSON = json.loads((FIXTURES / "cisa_kev_sample.json").read_text())


class TestFetchSuccess:
    @respx.mock
    async def test_returns_five_entries(self) -> None:
        respx.get(CISA_KEV_URL).mock(
            return_value=httpx.Response(200, json=SAMPLE_JSON)
        )
        client = CisaKevClient()
        entries = await client.fetch()
        assert len(entries) == 5

    @respx.mock
    async def test_first_entry_log4shell(self) -> None:
        respx.get(CISA_KEV_URL).mock(
            return_value=httpx.Response(200, json=SAMPLE_JSON)
        )
        client = CisaKevClient()
        entries = await client.fetch()
        entry = entries[0]
        assert entry.cve_id == "CVE-2021-44228"
        assert entry.vendor_project == "Apache"
        assert entry.product == "Log4j2"
        assert entry.notes == "Known as Log4Shell."

    @respx.mock
    async def test_date_added_parsed_as_date(self) -> None:
        respx.get(CISA_KEV_URL).mock(
            return_value=httpx.Response(200, json=SAMPLE_JSON)
        )
        client = CisaKevClient()
        entries = await client.fetch()
        for entry in entries:
            assert isinstance(entry.date_added, date)

    @respx.mock
    async def test_due_date_parsed_correctly(self) -> None:
        respx.get(CISA_KEV_URL).mock(
            return_value=httpx.Response(200, json=SAMPLE_JSON)
        )
        client = CisaKevClient()
        entries = await client.fetch()
        log4shell = entries[0]
        assert log4shell.due_date == date(2021, 12, 24)

    @respx.mock
    async def test_null_due_date_becomes_none(self) -> None:
        respx.get(CISA_KEV_URL).mock(
            return_value=httpx.Response(200, json=SAMPLE_JSON)
        )
        client = CisaKevClient()
        entries = await client.fetch()
        no_due = entries[2]
        assert no_due.cve_id == "CVE-2022-42003"
        assert no_due.due_date is None

    @respx.mock
    async def test_empty_string_notes_becomes_none(self) -> None:
        respx.get(CISA_KEV_URL).mock(
            return_value=httpx.Response(200, json=SAMPLE_JSON)
        )
        client = CisaKevClient()
        entries = await client.fetch()
        spring = entries[1]
        assert spring.cve_id == "CVE-2022-22965"
        assert spring.notes is None

    @respx.mock
    async def test_custom_url_is_used(self) -> None:
        custom_url = "https://custom.host/kev.json"
        respx.get(custom_url).mock(
            return_value=httpx.Response(200, json=SAMPLE_JSON)
        )
        client = CisaKevClient(url=custom_url)
        entries = await client.fetch()
        assert len(entries) == 5

    @respx.mock
    async def test_empty_catalog_returns_empty_list(self) -> None:
        empty_catalog = {
            "title": "KEV",
            "catalogVersion": "2024.01.01",
            "dateReleased": "2024-01-01T00:00:00Z",
            "count": 0,
            "vulnerabilities": [],
        }
        respx.get(CISA_KEV_URL).mock(
            return_value=httpx.Response(200, json=empty_catalog)
        )
        client = CisaKevClient()
        entries = await client.fetch()
        assert entries == []


class TestFetchErrors:
    @respx.mock
    async def test_404_raises_kev_fetch_error(self) -> None:
        respx.get(CISA_KEV_URL).mock(
            return_value=httpx.Response(404, text="Not Found")
        )
        client = CisaKevClient()
        with pytest.raises(KevFetchError):
            await client.fetch()

    @respx.mock
    async def test_500_raises_kev_fetch_error(self) -> None:
        respx.get(CISA_KEV_URL).mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )
        client = CisaKevClient()
        with pytest.raises(KevFetchError):
            await client.fetch()

    @respx.mock
    async def test_network_error_raises_kev_fetch_error(self) -> None:
        respx.get(CISA_KEV_URL).mock(side_effect=httpx.ConnectError("Connection refused"))
        client = CisaKevClient()
        with pytest.raises(KevFetchError, match="Error de red"):
            await client.fetch()

    @respx.mock
    async def test_timeout_raises_kev_fetch_error(self) -> None:
        respx.get(CISA_KEV_URL).mock(side_effect=httpx.TimeoutException("Timed out"))
        client = CisaKevClient()
        with pytest.raises(KevFetchError):
            await client.fetch()

    @respx.mock
    async def test_malformed_json_raises_kev_fetch_error(self) -> None:
        respx.get(CISA_KEV_URL).mock(
            return_value=httpx.Response(200, content=b"not-json")
        )
        client = CisaKevClient()
        with pytest.raises(KevFetchError):
            await client.fetch()
