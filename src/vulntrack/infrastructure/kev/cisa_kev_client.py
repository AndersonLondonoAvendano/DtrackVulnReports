"""Cliente para descargar el catálogo KEV de CISA."""
from __future__ import annotations

import logging
from datetime import date

import httpx
from pydantic import BaseModel, ConfigDict, Field

from vulntrack.domain.entities.kev_entry import KevEntry

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KevFetchError(Exception):
    """Fallo al descargar o parsear el catálogo KEV de CISA."""


class _KevVulnerability(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    cve_id: str = Field(..., alias="cveID")
    vendor_project: str = Field(..., alias="vendorProject")
    product: str
    vulnerability_name: str = Field(..., alias="vulnerabilityName")
    date_added: date = Field(..., alias="dateAdded")
    short_description: str = Field(..., alias="shortDescription")
    required_action: str = Field(..., alias="requiredAction")
    due_date: str | None = Field(None, alias="dueDate")
    notes: str | None = None

    def to_domain(self) -> KevEntry:
        due: date | None = None
        if self.due_date and self.due_date.strip():
            try:
                due = date.fromisoformat(self.due_date.strip())
            except ValueError:
                due = None
        return KevEntry(
            cve_id=self.cve_id,
            vendor_project=self.vendor_project,
            product=self.product,
            vulnerability_name=self.vulnerability_name,
            date_added=self.date_added,
            short_description=self.short_description,
            required_action=self.required_action,
            due_date=due,
            notes=self.notes or None,
        )


class _KevCatalog(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    title: str = ""
    catalog_version: str = Field("", alias="catalogVersion")
    date_released: str = Field("", alias="dateReleased")
    count: int = 0
    vulnerabilities: list[_KevVulnerability] = Field(default_factory=list)


class CisaKevClient:
    """Descarga el catálogo KEV de CISA y lo convierte a entidades de dominio."""

    def __init__(
        self,
        url: str = CISA_KEV_URL,
        timeout: float = 30.0,
    ) -> None:
        self._url = url
        self._timeout = timeout

    async def fetch(self) -> list[KevEntry]:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(self._url)
                resp.raise_for_status()
                catalog = _KevCatalog.model_validate(resp.json())
        except httpx.HTTPError as exc:
            raise KevFetchError(f"Error de red al descargar KEV: {exc}") from exc
        except Exception as exc:
            raise KevFetchError(f"Error inesperado al procesar KEV: {exc}") from exc

        entries = [v.to_domain() for v in catalog.vulnerabilities]
        logger.info("kev_catalog_fetched entries=%d", len(entries))
        return entries
