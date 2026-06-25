from __future__ import annotations

from functools import lru_cache
from typing import Any

from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuración central de la aplicación.

    Todas las variables sensibles (API key, URLs) se leen exclusivamente
    desde variables de entorno o archivo .env. Nunca se hardcodean.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Dependency-Track ──────────────────────────────────────────────────────
    dt_base_url: AnyHttpUrl = AnyHttpUrl("http://localhost:8081")
    dt_api_key: str = ""

    # ── Base de datos ─────────────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./data/vulntrack.db"

    # ── Sincronización ────────────────────────────────────────────────────────
    sync_interval_hours: int = 6

    # ── Catálogo KEV ─────────────────────────────────────────────────────────
    kev_stale_days: int = 7

    # ── Seguridad web ─────────────────────────────────────────────────────────
    allowed_origins: list[str] = ["http://localhost:8000", "http://127.0.0.1:8000"]

    # ── Aplicación ────────────────────────────────────────────────────────────
    debug: bool = False
    log_level: str = "INFO"
    app_version: str = "0.1.0"

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_origins(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v  # type: ignore[return-value]

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid:
            msg = f"log_level debe ser uno de: {valid}"
            raise ValueError(msg)
        return upper

    @property
    def dt_base_url_str(self) -> str:
        return str(self.dt_base_url).rstrip("/")


@lru_cache
def get_settings() -> Settings:
    """Singleton de configuración. Cacheado para toda la vida de la app."""
    return Settings()
