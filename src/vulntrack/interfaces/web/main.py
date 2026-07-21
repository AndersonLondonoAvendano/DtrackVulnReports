from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from vulntrack.config import Settings, get_settings
from vulntrack.infrastructure.persistence.database import AsyncSessionLocal
from vulntrack.logging_config import configure_logging, get_logger

logger = get_logger(__name__)

_TEMPLATES_DIR = __file__.replace("main.py", "templates")


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[type-arg]
    settings = get_settings()
    configure_logging(level=settings.log_level, debug=settings.debug)
    logger.info("vulntrack_starting", version=settings.app_version, debug=settings.debug)

    _run_migrations()

    import os
    if not os.getenv("PYTEST_CURRENT_TEST"):
        try:
            from vulntrack.infrastructure.scheduler.apscheduler_setup import setup_scheduler
            scheduler = setup_scheduler(app, settings)
            app.state.scheduler = scheduler
        except Exception as exc:
            logger.warning("scheduler_init_failed", error=str(exc))

    yield

    if hasattr(app.state, "scheduler") and app.state.scheduler.running:
        app.state.scheduler.shutdown(wait=False)
    logger.info("vulntrack_shutdown")


def _run_migrations() -> None:
    try:
        from alembic import command
        from alembic.config import Config

        alembic_cfg = Config("alembic.ini")
        command.upgrade(alembic_cfg, "head")
        logger.info("migrations_applied")
    except Exception as exc:
        logger.warning("migrations_skipped", error=str(exc))


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="VulnTrack Reports",
        description="Plataforma de reportes de vulnerabilidades sobre Dependency-Track",
        version=settings.app_version,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["*"],
    )

    import os
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    if os.path.isdir(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    _register_routers(app)

    @app.get("/health", tags=["sistema"], summary="Healthcheck")
    async def health() -> dict[str, Any]:
        db_status = await _check_db()
        dt_reachable = await _check_dt(settings)
        status = "ok" if db_status == "ok" else "degraded"
        http_status = 200 if status == "ok" else 503
        result: dict[str, Any] = {
            "status": status,
            "db": db_status,
            "dt_reachable": dt_reachable,
            "app_version": settings.app_version,
        }
        return JSONResponse(content=result, status_code=http_status)

    return app


def _register_routers(app: FastAPI) -> None:
    from vulntrack.interfaces.web.routers.sync import router as sync_router
    from vulntrack.interfaces.web.routers.sync import html_router as sync_html_router
    from vulntrack.interfaces.web.routers.dashboard import router as dashboard_router
    from vulntrack.interfaces.web.routers.projects import router as projects_router
    from vulntrack.interfaces.web.routers.projects import html_router as projects_html_router
    from vulntrack.interfaces.web.routers.reports import router as reports_router
    from vulntrack.interfaces.web.routers.reports import html_router as reports_html_router
    from vulntrack.interfaces.web.routers.prioritization import router as prioritization_router
    from vulntrack.interfaces.web.routers.prioritization import html_router as prioritization_html_router
    from vulntrack.interfaces.web.routers.kev import router as kev_router
    from vulntrack.interfaces.web.routers.kev import html_router as kev_html_router
    from vulntrack.interfaces.web.routers.remediation import router as remediation_router
    from vulntrack.interfaces.web.routers.remediation import html_router as remediation_html_router
    from vulntrack.interfaces.web.routers.config import router as config_router
    from vulntrack.interfaces.web.routers.config import html_router as config_html_router
    from vulntrack.interfaces.web.routers.sprints import router as sprints_router
    from vulntrack.interfaces.web.routers.sprints import html_router as sprints_html_router
    from vulntrack.interfaces.web.routers.treatments import router as treatments_router
    from vulntrack.interfaces.web.routers.metrics import router as metrics_router

    app.include_router(sync_router)
    app.include_router(sync_html_router)
    app.include_router(dashboard_router)
    app.include_router(projects_router)
    app.include_router(projects_html_router)
    app.include_router(reports_router)
    app.include_router(reports_html_router)
    app.include_router(prioritization_router)
    app.include_router(prioritization_html_router)
    app.include_router(kev_router)
    app.include_router(kev_html_router)
    app.include_router(remediation_router)
    app.include_router(remediation_html_router)
    app.include_router(config_router)
    app.include_router(config_html_router)
    app.include_router(sprints_router)
    app.include_router(sprints_html_router)
    app.include_router(treatments_router)
    app.include_router(metrics_router)


async def _check_dt(settings: Settings) -> bool:
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(
                f"{settings.dt_base_url_str}/api/v1/about",
                headers={"X-Api-Key": settings.dt_api_key},
            )
            return resp.is_success
    except Exception:
        return False


async def _check_db() -> str:
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        return "ok"
    except Exception as exc:
        logger.error("db_health_check_failed", error=str(exc))
        return "error"


app = create_app()
