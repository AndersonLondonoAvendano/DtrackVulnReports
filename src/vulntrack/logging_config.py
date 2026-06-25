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

    # Redirigir loggers estándar de uvicorn/fastapi a structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "fastapi", "sqlalchemy"):
        logging.getLogger(name).setLevel(log_level)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Retorna un logger estructurado listo para usar."""
    return structlog.get_logger(name)  # type: ignore[return-value]
