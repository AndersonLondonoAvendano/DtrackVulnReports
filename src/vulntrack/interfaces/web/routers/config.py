"""T-079: Router de configuración."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from vulntrack.interfaces.web._shared import templates
from vulntrack.interfaces.web.dependencies import (
    get_app_settings,
    get_app_settings_repo,
    get_dt_client,
)
from vulntrack.interfaces.web.schemas.config import (
    ConfigOut,
    TestConnectionOut,
    UpdateConfigRequest,
)

router = APIRouter(prefix="/api/v1/config", tags=["configuracion"])
html_router = APIRouter(tags=["configuracion-html"])


@router.get("", response_model=ConfigOut)
async def get_config(
    repo: Any = Depends(get_app_settings_repo),  # noqa: B008
    settings: Any = Depends(get_app_settings),  # noqa: B008
) -> ConfigOut:
    cfg = await repo.get()
    return ConfigOut(
        dt_base_url=settings.dt_base_url_str,
        sync_interval_hours=cfg.sync_interval_hours,
        kev_stale_days=cfg.kev_stale_days,
        w_cvss_weight=cfg.w_cvss_weight,
        w_epss_weight=cfg.w_epss_weight,
        w_kev_weight=cfg.w_kev_weight,
        kev_minimum_score=cfg.kev_minimum_score,
        epss_high_threshold=cfg.epss_high_threshold,
        cvss_high_threshold=cfg.cvss_high_threshold,
    )


@router.patch("", response_model=ConfigOut)
async def update_config(
    body: UpdateConfigRequest,
    repo: Any = Depends(get_app_settings_repo),  # noqa: B008
    settings: Any = Depends(get_app_settings),  # noqa: B008
) -> ConfigOut:
    fields = {k: v for k, v in body.model_dump().items() if v is not None}
    if not fields:
        raise HTTPException(status_code=422, detail="Sin campos para actualizar")
    cfg = await repo.update(**fields)
    return ConfigOut(
        dt_base_url=settings.dt_base_url_str,
        sync_interval_hours=cfg.sync_interval_hours,
        kev_stale_days=cfg.kev_stale_days,
        w_cvss_weight=cfg.w_cvss_weight,
        w_epss_weight=cfg.w_epss_weight,
        w_kev_weight=cfg.w_kev_weight,
        kev_minimum_score=cfg.kev_minimum_score,
        epss_high_threshold=cfg.epss_high_threshold,
        cvss_high_threshold=cfg.cvss_high_threshold,
    )


@router.post("/test-connection", response_model=TestConnectionOut)
async def test_connection(
    dt_client: Any = Depends(get_dt_client),  # noqa: B008
) -> TestConnectionOut:
    import httpx

    try:
        version = await dt_client.get_server_version()
        return TestConnectionOut(ok=True, dt_version=version)
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 404:
            msg = (
                f"Endpoint no encontrado (HTTP 404). "
                f"Verifique que DT_BASE_URL apunta al API server y que /api/v1/about existe."
            )
        elif status in (401, 403):
            msg = f"Sin autorización (HTTP {status}). Verifique DT_API_KEY y los permisos del team."
        else:
            msg = f"Error HTTP {status} al contactar {exc.request.url}."
        return TestConnectionOut(ok=False, error=msg)
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        return TestConnectionOut(
            ok=False,
            error=f"No se puede conectar al host ({type(exc).__name__}). Verifique DT_BASE_URL.",
        )
    except Exception as exc:
        return TestConnectionOut(ok=False, error=str(exc))


@html_router.get("/settings", response_class=HTMLResponse, include_in_schema=False)
async def settings_html(
    request: Request,
    repo: Any = Depends(get_app_settings_repo),  # noqa: B008
    settings: Any = Depends(get_app_settings),  # noqa: B008
) -> Any:
    cfg = await repo.get()
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "titulo": "Configuración",
            "cfg": cfg,
            "dt_base_url": settings.dt_base_url_str,
        },
    )
