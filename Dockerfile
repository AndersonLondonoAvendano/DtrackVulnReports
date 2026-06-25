FROM python:3.12-slim AS base

# Dependencias de sistema para WeasyPrint (GTK/Pango/Cairo)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    fonts-liberation \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Instalar uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copiar archivos de dependencias primero (capa cacheable)
COPY pyproject.toml ./
RUN uv sync --no-dev --frozen 2>/dev/null || uv sync --no-dev

# Copiar código fuente
COPY src/ src/
COPY alembic/ alembic/
COPY alembic.ini .

# Crear directorio de datos (volumen en docker-compose)
RUN mkdir -p /app/data

# Usuario no-root
RUN useradd -m -u 1000 vulntrack && chown -R vulntrack:vulntrack /app
USER vulntrack

EXPOSE 8000

# Ejecutar migraciones y luego arrancar la app
CMD ["sh", "-c", "uv run alembic upgrade head && uv run uvicorn vulntrack.interfaces.web.main:app --host 0.0.0.0 --port 8000"]
