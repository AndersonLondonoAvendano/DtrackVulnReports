# VulnTrack Reports

Plataforma de reportes de vulnerabilidades sobre [Dependency-Track](https://dependencytrack.org/).
Genera reportes ejecutivos trimestrales/mensuales en formato Word, Excel y PDF con métricas de avance,
priorización inteligente (CVSS + EPSS + KEV) y planes de remediación gestionados desde la interfaz web.

---

## Requisitos previos

| Herramienta | Versión mínima |
|---|---|
| Docker | 24.x |
| Docker Compose | v2.x (`docker compose`) |
| Dependency-Track | 4.10+ (con API habilitada) |

> Para desarrollo local sin Docker se necesita **Python 3.12+** y **uv** (`pip install uv`).

---

## Configuración

### 1. Copiar el archivo de variables de entorno

```bash
cp .env.example .env
```

### 2. Editar `.env` con los valores reales

```dotenv
# URL pública de tu instancia de Dependency-Track
DT_BASE_URL=http://your-dt-host:8081

# API Key de DT (Administración → Access Management → API Keys)
DT_API_KEY=your-api-key-here

# Ruta de la base de datos SQLite (relativa al contenedor; el volumen ./data la persiste)
DATABASE_URL=sqlite+aiosqlite:///./data/vulntrack.db

# Intervalo de sincronización automática en horas (default: 6)
SYNC_INTERVAL_HOURS=6

# Umbral de "catálogo KEV obsoleto" en días (default: 7)
KEV_STALE_DAYS=7
```

> Las variables sin valor por defecto obligatorio son `DT_BASE_URL` y `DT_API_KEY`.
> Consulta `.env.example` para la lista completa de opciones.

---

## Arranque

```bash
docker compose up --build
```

La aplicación queda disponible en **http://localhost:8000**.

Al iniciar, se ejecutan automáticamente las migraciones de base de datos (Alembic) y se arranca
el scheduler de sincronización periódica.

### Verificar que la app está lista

```bash
curl http://localhost:8000/health
# {"status":"ok","db":"ok","dt_reachable":true,"app_version":"0.1.0"}
```

- `status: ok` → todo operativo.
- `status: degraded` → la base de datos no responde (revisa el volumen `./data`).
- `dt_reachable: false` → la URL de DT no es accesible desde el contenedor (revisa `DT_BASE_URL`).

---

## Primera sincronización

1. Abre **http://localhost:8000** en el navegador.
2. En el dashboard, pulsa el botón **"Sincronizar ahora"**.
3. El estado cambia a `syncing` y vuelve a `idle` al terminar (polling automático cada 30 s).
4. Alternativamente, vía API:

```bash
curl -X POST http://localhost:8000/api/v1/sync/run
# {"status":"triggered","message":"Sincronización iniciada en background"}
```

La primera sincronización puede tardar varios minutos dependiendo del número de proyectos en DT.

---

## Generación del primer reporte

### Desde la interfaz web

1. Ve a **http://localhost:8000/reports**.
2. Selecciona tipo **Portfolio**, período **Trimestral**, elige el trimestre y año.
3. Marca los formatos deseados (Excel, Word, PDF).
4. Pulsa **"Generar reporte"** — el archivo se descarga automáticamente.

### Desde la API

```bash
curl -X POST http://localhost:8000/api/v1/reports/generate \
  -H "Content-Type: application/json" \
  -d '{"period":"quarterly","quarter":"Q2","year":2026,"formats":["xlsx"]}' \
  --output Reporte_Q2_2026.xlsx
```

El nombre del archivo sigue el patrón `Reporte_Portafolio_{Q}{año}.{formato}`.

---

## Estructura del proyecto

```
vulntrack/
├── domain/                  # Capa de dominio — entidades, puertos, servicios
│   ├── entities/            # Project, Finding, MetricSnapshot, KevEntry, Remediation
│   ├── services/            # PrioritizationService, AdvanceCalculator, KevMatcher
│   ├── ports/               # Interfaces (Protocol) hacia infraestructura
│   └── value_objects/       # Severity, PriorityScore, DateRange, ReportPeriod
├── application/             # Casos de uso — sin dependencias de framework
│   ├── sync/                # SyncPortfolio, SyncKev
│   ├── queries/             # DashboardQuery, ProjectDetailQuery, PrioritizedFindingsQuery
│   ├── reports/             # BuildReportData, GeneratePortfolioReport, GenerateProjectReport
│   └── remediation/         # CreatePlan, UpdateTask, SuggestTasks, ExportPlan
├── infrastructure/          # Implementaciones concretas
│   ├── persistence/         # Modelos ORM, repositorios SQLAlchemy, migraciones Alembic
│   ├── dt/                  # DtHttpClient, modelos de respuesta DT
│   ├── kev/                 # CisaKevClient
│   ├── reports/             # DocxGenerator, XlsxGenerator, PdfGenerator, ChartBuilder
│   └── scheduler/           # APScheduler setup (sync_portfolio + sync_kev jobs)
└── interfaces/
    └── web/                 # FastAPI app, routers, templates Jinja2, schemas Pydantic
        ├── routers/         # sync, dashboard, projects, reports, prioritization, kev,
        │                    #   remediation, config
        ├── schemas/         # DTOs de request/response
        ├── templates/       # HTML con Tailwind CSS + HTMX
        └── dependencies.py  # Contenedor DI con Depends()

tests/
├── domain/                  # Tests unitarios de capa de dominio
├── application/             # Tests de casos de uso con mocks
├── infrastructure/          # Tests de repositorios con SQLite en memoria
└── web/                     # Tests de routers (dependency_overrides) + E2E
```

Consulta [docs/specs/plan.md](docs/specs/plan.md) para la arquitectura detallada y
[docs/specs/tasks.md](docs/specs/tasks.md) para el estado de implementación.

---

## Comandos de desarrollo

### Instalar dependencias

```bash
uv sync
```

### Ejecutar la app en desarrollo (auto-reload)

```bash
uv run uvicorn vulntrack.interfaces.web.main:app --reload
```

### Ejecutar tests

```bash
uv run pytest                           # todos los tests
uv run pytest tests/web/test_e2e.py -v  # solo E2E
uv run pytest --cov=src/vulntrack --cov-report=term-missing  # con cobertura
```

### Linting y formateo

```bash
uv run ruff check src/ tests/
uv run ruff format src/ tests/
```

### Type checking

```bash
uv run mypy src/vulntrack/
```

### Migraciones de base de datos

```bash
# Aplicar migraciones pendientes
uv run alembic upgrade head

# Crear una nueva migración
uv run alembic revision --autogenerate -m "descripcion"

# Ver historial
uv run alembic history
```

### Actualizar catálogo KEV manualmente

```bash
curl -X POST http://localhost:8000/api/v1/kev/refresh
```

---

## Variables de entorno completas

| Variable | Default | Descripción |
|---|---|---|
| `DT_BASE_URL` | `http://localhost:8081` | URL base de la instancia DT |
| `DT_API_KEY` | *(obligatoria)* | API Key de Dependency-Track |
| `DATABASE_URL` | `sqlite+aiosqlite:///./data/vulntrack.db` | Cadena de conexión SQLAlchemy |
| `SYNC_INTERVAL_HOURS` | `6` | Horas entre sincronizaciones automáticas |
| `KEV_STALE_DAYS` | `7` | Días máximos sin actualizar el catálogo KEV |
| `ALLOWED_ORIGINS` | `http://localhost:8000,...` | CORS origins permitidos (separados por coma) |
| `DEBUG` | `false` | Activa logging detallado y recarga de templates |
| `LOG_LEVEL` | `INFO` | Nivel de logging (`DEBUG`/`INFO`/`WARNING`/`ERROR`) |
| `APP_VERSION` | `0.1.0` | Versión mostrada en `/health` y en reportes |

---

## Licencia

Uso interno. Sin licencia de distribución pública.
