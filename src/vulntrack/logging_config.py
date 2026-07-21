from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(level: str = "INFO", *, debug: bool = False) -> None:
    """Configura structlog para la aplicación.

    En modo debug: salida coloreada y legible para humanos.
    En producción: JSON estructurado por línea (apto para log aggregators).
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if debug:
        processors: list[structlog.types.Processor] = [
            *shared_processors,
            structlog.dev.ConsoleRenderer(colors=True),
        ]
    else:
        processors = [
            *shared_processors,
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Redirigir loggers estándar de uvicorn/fastapi/vulntrack a structlog
    logging.basicConfig(
        format="%(levelname)s [%(name)s] %(message)s",
        stream=sys.stdout,
        level=log_level,
        force=True,  # forzar aunque uvicorn ya haya instalado handlers
    )
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "fastapi",
                 "sqlalchemy", "vulntrack"):
        logging.getLogger(name).setLevel(log_level)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Retorna un logger estructurado listo para usar."""
    return structlog.get_logger(name)  # type: ignore[return-value]


def reenable_vulntrack_loggers() -> None:
    """Re-habilita loggers deshabilitados por el dictConfig de uvicorn.

    Uvicorn llama a dictConfig(disable_existing_loggers=True) DESPUÉS de que
    el lifespan arranca, deshabilitando todos los loggers stdlib creados al
    importar módulos (incluyendo vulntrack.*). Esta función los re-habilita y
    asegura que vulntrack tenga un handler directo a stdout.
    """
    for obj in logging.Logger.manager.loggerDict.values():
        if isinstance(obj, logging.Logger) and obj.disabled:
            obj.disabled = False

    vl = logging.getLogger("vulntrack")
    if not vl.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("%(levelname)s [%(name)s] %(message)s"))
        vl.addHandler(h)
        vl.propagate = False
