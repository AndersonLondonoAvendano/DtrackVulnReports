"""Instancias compartidas de Jinja2Templates y constantes web."""
from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

from vulntrack.interfaces.web.pagination_utils import build_page_range

_TEMPLATES_DIR = Path(__file__).parent / "templates"

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
templates.env.globals["build_page_range"] = build_page_range
