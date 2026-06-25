"""Fixtures compartidas para todos los tests."""
from __future__ import annotations

import os
import sys

import pytest

# En Windows, registrar el directorio de Python en la búsqueda de DLLs
# para que extensiones C como greenlet encuentren vcruntime140.dll / MSVCP140.dll
if sys.platform == "win32":
    import importlib.util
    _python_home = os.path.dirname(sys.executable)
    if hasattr(os, "add_dll_directory"):
        os.add_dll_directory(_python_home)
        # También intentar directorio de Scripts (venv)
        _scripts = os.path.join(os.path.dirname(_python_home), "Scripts")
        if os.path.isdir(_scripts):
            os.add_dll_directory(_scripts)

# Configurar variables de entorno de prueba ANTES de importar la app
os.environ.setdefault("DT_BASE_URL", "http://dt-test.local:8081")
os.environ.setdefault("DT_API_KEY", "test-api-key-fake")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("LOG_LEVEL", "WARNING")


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"
