# Plan técnico — VulnTrack Reports

> **Versión:** 1.0  
> **Fecha:** 2026-06-23  
> **Trazabilidad:** Implementa spec.md v1.1, respeta constitution.md v1.0.

---

## 1. Visión de arquitectura

El sistema sigue arquitectura **hexagonal (puertos y adaptadores)** organizada en cuatro capas. La regla de dependencia es estricta: las capas internas no conocen las externas.

```
┌─────────────────────────────────────────────────────┐
│  interfaces/web  (FastAPI: routers, schemas, vistas) │
├─────────────────────────────────────────────────────┤
│  application     (casos de uso / orquestación)       │
├─────────────────────────────────────────────────────┤
│  domain          (entidades, value objects, puertos)  │
├─────────────────────────────────────────────────────┤
│  infrastructure  (adaptadores: DT, BD, reportes, KEV)│
└─────────────────────────────────────────────────────┘
        ↑  todas las dependencias apuntan hacia adentro
```

**Flujo de una petición típica (generar reporte):**

```
Browser → FastAPI Router → GeneratePortfolioReport (use case)
       → ProjectRepository (port) ← SqliteProjectRepository (adapter)
       → FindingRepository (port) ← SqliteFindingRepository (adapter)
       → PrioritizationService (domain)
       → ReportGenerator (port) ← DocxGenerator | XlsxGenerator | PdfGenerator (adapters)
       → StreamingResponse → Browser
```

---

## 2. Stack tecnológico

| Componente | Tecnología elegida | Alternativa considerada | Razón de elección |
|------------|--------------------|------------------------|-------------------|
| Runtime | Python 3.12 | 3.11 | `tomllib` nativo, `@override`, mejoras de performance |
| Web framework | FastAPI 0.115.x | Django, Flask | Async nativo, tipado con Pydantic, documentación OpenAPI auto-generada |
| Validación / DTOs | Pydantic v2 | dataclasses | Velocidad (Rust core), integración FastAPI |
| Cliente HTTP (DT) | httpx (async) | aiohttp, requests | API limpia, soporte async/sync, retry con tenacity |
| ORM | SQLAlchemy 2.x (async) | SQLModel, Tortoise | Madurez, soporte SQLite + PostgreSQL, integración Alembic |
| Migraciones | Alembic | Yoyo, liquidbase | Estándar de facto con SQLAlchemy |
| Base de datos local | SQLite | PostgreSQL | Sin dependencias externas; abstracción permite migrar |
| Scheduler | APScheduler 3.x | Celery + Redis | In-process, cero dependencias extra; suficiente para ~22 proyectos |
| Templates web | Jinja2 + HTMX | React, Vue, SvelteKit | Sin build step, stack Python puro, interactividad suficiente |
| Reportes Word | python-docx | ONLYOFFICE API | Control total del formato; reproducción exacta del reporte de referencia |
| Reportes Excel | openpyxl | xlsxwriter | Soporte de estilos, heatmap, charts nativos |
| Gráficas (embed) | matplotlib | plotly | Salida PNG embebible en docx/pdf; plotly genera HTML/JS |
| PDF | WeasyPrint | ReportLab | Renderiza HTML/CSS → PDF; usa las mismas plantillas Jinja2 del web UI |
| Logs | structlog | loguru, logging std | JSON estructurado, contexto enriquecido, integración FastAPI |
| Lint / format | ruff | pylint + black + isort | Una sola herramienta, rápido (Rust) |
| Tipado estático | mypy (strict en domain/app) | pyright | Ecosistema más maduro, integración CI |
| Tests | pytest + pytest-asyncio | unittest | Fixtures, async support, plugins |
| Dependencias | uv | Poetry, pip-tools | Velocidad, lock file reproducible |
| Contenedores | Docker + docker-compose v2 | Podman | Estándar, disponible en Windows/Mac/Linux |

---

## 3. Estructura de carpetas

```
DtrackVulnReports/
├── docs/specs/                   ← artefactos SDD
├── src/
│   └── vulntrack/
│       ├── __init__.py
│       │
│       ├── domain/               ← SIN dependencias de framework
│       │   ├── entities/
│       │   │   ├── project.py
│       │   │   ├── finding.py
│       │   │   ├── metric_snapshot.py
│       │   │   ├── remediation.py    # Plan + Task
│       │   │   └── kev_entry.py
│       │   ├── value_objects/
│       │   │   ├── severity.py       # Enum: CRITICAL/HIGH/MEDIUM/LOW/UNASSIGNED
│       │   │   ├── priority_score.py # Dataclass: score + band + breakdown
│       │   │   ├── date_range.py     # DateRange con validación inicio < fin
│       │   │   └── report_period.py  # Enum: WEEKLY/MONTHLY/QUARTERLY/CUSTOM
│       │   ├── ports/                # Interfaces (ABC)
│       │   │   ├── dt_client.py
│       │   │   ├── project_repository.py
│       │   │   ├── finding_repository.py
│       │   │   ├── snapshot_repository.py
│       │   │   ├── remediation_repository.py
│       │   │   ├── kev_repository.py
│       │   │   ├── report_generator.py
│       │   │   └── ticketing_port.py      # Vacío; para Jira/GLPI futuro
│       │   └── services/
│       │       ├── prioritization.py      # Fórmula CVSS+EPSS+KEV; pesos configurables
│       │       ├── advance_calculator.py  # Nuevas, tratadas, variación por período
│       │       └── kev_matcher.py         # Cruce findings ↔ KEV catalog
│       │
│       ├── application/           ← Casos de uso; depende solo de domain/ports
│       │   ├── sync/
│       │   │   ├── sync_portfolio.py      # Orquesta sync completo
│       │   │   └── sync_kev.py
│       │   ├── reports/
│       │   │   ├── build_report_data.py   # Ensamblado de ReportData
│       │   │   ├── generate_portfolio_report.py
│       │   │   └── generate_project_report.py
│       │   ├── remediation/
│       │   │   ├── create_plan.py
│       │   │   ├── update_task.py
│       │   │   ├── suggest_tasks.py       # Recomendaciones inteligentes
│       │   │   └── export_plan.py
│       │   └── queries/
│       │       ├── dashboard_query.py
│       │       ├── project_detail_query.py
│       │       ├── prioritized_findings_query.py
│       │       └── kev_findings_query.py
│       │
│       ├── infrastructure/        ← Adaptadores concretos
│       │   ├── dt/
│       │   │   ├── client.py              # DtHttpClient implements DtClientPort
│       │   │   └── response_models.py     # Pydantic models para respuestas DT
│       │   ├── persistence/
│       │   │   ├── database.py            # Engine, Session factory
│       │   │   ├── orm_models.py          # SQLAlchemy ORM (tablas)
│       │   │   └── repositories/
│       │   │       ├── project_repo.py
│       │   │       ├── finding_repo.py
│       │   │       ├── snapshot_repo.py
│       │   │       ├── remediation_repo.py
│       │   │       └── kev_repo.py
│       │   ├── reports/
│       │   │   ├── chart_builder.py       # matplotlib → PNG en memoria
│       │   │   ├── docx_generator.py
│       │   │   ├── xlsx_generator.py
│       │   │   └── pdf_generator.py       # WeasyPrint + Jinja2
│       │   ├── kev/
│       │   │   └── cisa_kev_client.py     # httpx → JSON CISA KEV
│       │   └── scheduler/
│       │       └── apscheduler_setup.py
│       │
│       ├── interfaces/
│       │   └── web/
│       │       ├── main.py                # FastAPI app factory
│       │       ├── dependencies.py        # DI: inyecta repositorios y servicios
│       │       ├── config.py              # pydantic-settings, lee .env
│       │       ├── routers/
│       │       │   ├── dashboard.py
│       │       │   ├── projects.py
│       │       │   ├── sync.py
│       │       │   ├── reports.py
│       │       │   ├── prioritization.py
│       │       │   ├── kev.py
│       │       │   └── remediation.py
│       │       ├── schemas/               # Pydantic DTOs (request/response)
│       │       │   ├── project.py
│       │       │   ├── finding.py
│       │       │   ├── report.py
│       │       │   └── remediation.py
│       │       └── templates/             # Jinja2
│       │           ├── base.html
│       │           ├── dashboard.html
│       │           ├── projects/
│       │           │   ├── list.html
│       │           │   └── detail.html
│       │           ├── reports/
│       │           │   └── generate.html
│       │           ├── prioritization/
│       │           │   └── index.html
│       │           ├── kev/
│       │           │   └── index.html
│       │           └── remediation/
│       │               ├── plan_list.html
│       │               └── plan_detail.html
│       │
│       └── config.py                      # Settings singleton (pydantic-settings)
│
├── tests/
│   ├── conftest.py
│   ├── domain/
│   │   ├── test_prioritization.py
│   │   ├── test_advance_calculator.py
│   │   └── test_kev_matcher.py
│   ├── application/
│   │   ├── test_sync_portfolio.py
│   │   ├── test_generate_report.py
│   │   └── test_suggest_tasks.py
│   ├── infrastructure/
│   │   ├── test_dt_client.py              # httpx mock via respx
│   │   └── test_repositories.py           # SQLite en memoria
│   └── web/
│       └── test_routers.py                # TestClient FastAPI
│
├── alembic/
│   ├── alembic.ini
│   └── versions/
├── pyproject.toml
├── .env.example
├── .pre-commit-config.yaml
├── Dockerfile
└── docker-compose.yml
```

---

## 4. Modelo de datos

### 4.1 Entidades de dominio (en `domain/entities/`)

```python
# Raíz de identidad — no depende de SQLAlchemy
@dataclass
class Project:
    uuid: str           # UUID de DT (PK natural)
    name: str
    version: str | None
    description: str | None
    last_bom_import: datetime | None
    last_synced_at: datetime

@dataclass
class MetricSnapshot:
    id: int             # PK local autoincrement
    project_uuid: str   # FK → Project
    snapshot_date: date
    critical: int
    high: int
    medium: int
    low: int
    unassigned: int
    total: int          # Computed: sum of above
    risk_score: float
    source: SnapshotSource  # DT_CURRENT | DT_HISTORICAL | LOCAL

@dataclass
class Finding:
    id: int
    project_uuid: str
    dt_finding_uuid: str    # UUID del finding en DT
    component_name: str
    component_version: str | None
    component_group: str | None
    vuln_id: str            # CVE-XXXX-XXXX | GHSA-xxx | etc.
    vuln_source: str        # NVD | OSS_INDEX | GITHUB | etc.
    severity: Severity      # Value object (enum)
    cvss_v3_base_score: float | None
    epss_score: float | None
    epss_percentile: float | None
    attributed_on: datetime | None
    suppressed: bool
    last_synced_at: datetime

@dataclass
class KevEntry:
    cve_id: str             # PK: CVE-XXXX-XXXX
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: date
    short_description: str
    required_action: str
    due_date: date | None
    notes: str | None

@dataclass
class RemediationPlan:
    id: int
    project_uuid: str
    name: str
    description: str | None
    created_at: datetime
    updated_at: datetime

@dataclass
class RemediationTask:
    id: int
    plan_id: int
    finding_id: int | None          # Nullable: tarea general sin finding
    title: str
    description: str | None
    assignee: str | None
    status: TaskStatus              # PENDING | IN_PROGRESS | COMPLETED | DISCARDED
    priority_band: PriorityBand     # IMMEDIATE | HIGH | MEDIUM | LOW
    recommended_action: str | None  # Generado por suggest_tasks
    target_date: date | None
    completed_at: datetime | None
    notes: str | None
    created_at: datetime
    updated_at: datetime
```

### 4.2 Tablas ORM (SQLAlchemy, `infrastructure/persistence/orm_models.py`)

```
projects               findings
──────────             ─────────────────────
uuid PK                id PK
name                   project_uuid FK
version                dt_finding_uuid UNIQUE
description            component_name
last_bom_import        component_version
last_synced_at         component_group
created_at             vuln_id
updated_at             vuln_source
                       severity
                       cvss_v3_base_score
metric_snapshots       epss_score
──────────────────     epss_percentile
id PK                  attributed_on
project_uuid FK        suppressed
snapshot_date          last_synced_at
critical               created_at
high                   updated_at
medium
low                    kev_entries
unassigned             ───────────
total                  cve_id PK
risk_score             vendor_project
source                 product
created_at             vulnerability_name
                       date_added
remediation_plans      short_description
──────────────────     required_action
id PK                  due_date
project_uuid FK        notes
name                   catalog_updated_at
description
created_at             app_settings (singleton id=1)
updated_at             ─────────────────────────────
                       id PK (always 1)
remediation_tasks      sync_interval_hours
──────────────────     kev_stale_days
id PK                  last_sync_at
plan_id FK             last_kev_update_at
finding_id FK NULL     w_cvss_weight
title                  w_epss_weight
description            w_kev_weight
assignee               kev_minimum_score
status                 epss_high_threshold
priority_band          cvss_high_threshold
recommended_action     updated_at
target_date
completed_at
notes
created_at
updated_at
```

**Índices críticos:**
- `findings(project_uuid, severity)` — consultas de dashboard
- `findings(vuln_id)` — cruce KEV
- `findings(attributed_on)` — cálculo de nuevas por período
- `metric_snapshots(project_uuid, snapshot_date)` — cálculo de avance
- `kev_entries(cve_id)` — lookup O(1) en cruce

### 4.3 Nota sobre API key

`DT_API_KEY` **nunca se almacena en la base de datos**. Se lee exclusivamente desde variables de entorno al arrancar la app. Si cambia, se actualiza el `.env` y se reinicia el contenedor.

---

## 5. Configuración y secretos (`config.py`)

```python
# Todas las variables configurables con pydantic-settings
class Settings(BaseSettings):
    # DT — SECRETOS (solo desde env, nunca en DB)
    dt_base_url: AnyHttpUrl          # DT_BASE_URL
    dt_api_key: SecretStr            # DT_API_KEY

    # Sync
    sync_interval_hours: int = 6     # SYNC_INTERVAL_HOURS

    # Base de datos
    database_url: str = "sqlite+aiosqlite:///./vulntrack.db"  # DATABASE_URL

    # KEV
    kev_stale_days: int = 7          # KEV_STALE_DAYS

    # Seguridad web
    allowed_origins: list[str] = ["http://localhost:8000"]    # ALLOWED_ORIGINS

    # App
    debug: bool = False              # DEBUG
    log_level: str = "INFO"          # LOG_LEVEL

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")
```

**.env.example** (sin secretos reales):
```ini
DT_BASE_URL=http://localhost:8081
DT_API_KEY=your-api-key-here
DATABASE_URL=sqlite+aiosqlite:///./vulntrack.db
SYNC_INTERVAL_HOURS=6
KEV_STALE_DAYS=7
DEBUG=false
LOG_LEVEL=INFO
```

---

## 6. Contratos de API interna (FastAPI)

Todos los endpoints JSON tienen prefijo `/api/v1/`. Las vistas web HTML no tienen prefijo.

### Sync
| Método | Path | Descripción |
|--------|------|-------------|
| POST | `/api/v1/sync/run` | Dispara sincronización completa (async background) → 202 |
| GET | `/api/v1/sync/status` | Estado actual: running/idle, progreso, última sync |

### Dashboard
| Método | Path | Descripción |
|--------|------|-------------|
| GET | `/api/v1/dashboard` | KPIs del portafolio: vigentes por severidad, nuevas/tratadas del período, proyectos en cero |

### Proyectos
| Método | Path | Descripción |
|--------|------|-------------|
| GET | `/api/v1/projects` | Lista paginada con métricas actuales; soporta `?sort=critical&order=desc&search=` |
| GET | `/api/v1/projects/{uuid}` | Detalle: métricas + findings + plan de remediación |

### Hallazgos (findings)
| Método | Path | Descripción |
|--------|------|-------------|
| GET | `/api/v1/findings` | Lista filtrable: `?project=&severity=&kev_only=true&page=&size=` |
| GET | `/api/v1/findings/prioritized` | Lista ordenada por priority_score DESC |
| GET | `/api/v1/findings/thresholds` | Filtro por umbrales CVSS/EPSS configurables |

### Reportes
| Método | Path | Body / Params | Descripción |
|--------|------|--------------|-------------|
| POST | `/api/v1/reports/generate` | `{type, period, date_range, projects, formats}` | Genera y devuelve archivo (StreamingResponse) |

```json
// Ejemplo body POST /api/v1/reports/generate
{
  "report_type": "portfolio",        // "portfolio" | "project"
  "project_uuid": null,              // UUID si type=project
  "period": "quarterly",             // "weekly"|"monthly"|"quarterly"|"custom"
  "date_from": "2026-04-01",         // si period=custom
  "date_to": "2026-06-16",           // si period=custom
  "quarter": "Q2",                   // si period=quarterly: Q1|Q2|Q3|Q4
  "year": 2026,
  "formats": ["docx", "xlsx", "pdf"] // uno o más
}
```

Si se piden múltiples formatos: responde con ZIP. Si es uno: StreamingResponse directo.

### KEV
| Método | Path | Descripción |
|--------|------|-------------|
| GET | `/api/v1/kev/status` | Fecha de última actualización, count de entradas, si está desactualizado |
| POST | `/api/v1/kev/refresh` | Descarga catálogo CISA KEV, actualiza BD → 202 |
| GET | `/api/v1/kev/findings` | Findings del portafolio presentes en KEV |

### Remediación
| Método | Path | Descripción |
|--------|------|-------------|
| GET | `/api/v1/remediation/plans` | Lista de planes por proyecto |
| POST | `/api/v1/remediation/plans` | Crear plan |
| GET | `/api/v1/remediation/plans/{id}` | Detalle del plan con tareas |
| POST | `/api/v1/remediation/plans/{id}/suggest` | Generar tareas sugeridas automáticamente |
| PATCH | `/api/v1/remediation/tasks/{id}` | Actualizar estado/asignee/notas |
| POST | `/api/v1/remediation/plans/{id}/export` | Exportar plan → .xlsx o .pdf (StreamingResponse) |

### Configuración
| Método | Path | Descripción |
|--------|------|-------------|
| GET | `/api/v1/config` | Configuración actual (sin API key) |
| PATCH | `/api/v1/config` | Actualizar sync_interval, pesos, umbrales |
| POST | `/api/v1/config/test-connection` | Probar conexión a DT → `{ok: bool, dt_version: str}` |
| GET | `/health` | Healthcheck: DB + DT opcional → `{status, db, dt_reachable}` |

---

## 7. Estrategia de sincronización con Dependency-Track

### 7.1 Algoritmo de sync completo

```
SyncPortfolio.execute()
│
├─ 1. GET /api/v1/project?pageNumber=1&pageSize=100
│      Repetir hasta pageNumber * pageSize ≥ X-Total-Count
│      → lista de proyectos raw
│
├─ 2. Para cada proyecto (concurrente, semáforo máx. 5):
│      ├─ GET /api/v1/metrics/project/{uuid}/current
│      │    → métricas actuales (critical/high/medium/low/unassigned/riskScore)
│      └─ Upsert en tabla projects + guardar MetricSnapshot de hoy
│
├─ 3. Para cada proyecto (concurrente, semáforo máx. 3):
│      ├─ GET /api/v1/finding/project/{uuid}
│      │    (DT no pagina findings con header; usa parámetro size=1000)
│      └─ Upsert findings en BD; conservar attributed_on original
│
└─ 4. Marcar last_sync_at en app_settings
```

### 7.2 Backfill histórico (primera sincronización)

```
Para cada proyecto:
  GET /api/v1/metrics/project/{uuid}/days/90
  → Guardar un MetricSnapshot por día (source=DT_HISTORICAL)
  → Si ya existe snapshot para ese día/proyecto → skip (idempotente)
```

### 7.3 Manejo de errores y reintentos

```python
# tenacity para reintentos con backoff exponencial
@retry(
    wait=wait_exponential(multiplier=1, min=2, max=30),
    stop=stop_after_attempt(3),
    retry=retry_if_exception_type(httpx.HTTPStatusError),
    reraise=True,
)
async def _get_with_retry(url, ...): ...
```

- Rate limiting: semáforo `asyncio.Semaphore(5)` para llamadas concurrentes a DT.
- Si un proyecto falla: se registra el error, se continúa con los demás (sync parcial).
- El resultado final indica: `{synced: N, failed: M, projects_with_errors: [...]}`.

### 7.4 Scheduler (APScheduler)

```python
# Arranca junto con la app FastAPI (lifespan)
scheduler = AsyncIOScheduler(timezone="UTC")
scheduler.add_job(sync_portfolio_job, "interval", hours=settings.sync_interval_hours)
scheduler.add_job(take_daily_snapshot_job, "cron", hour=1, minute=0)  # 01:00 UTC
```

---

## 8. Arquitectura de generación de reportes

```
                     ReportData (dataclass puro)
                     ┌────────────────────────────┐
                     │ portfolio_metrics           │
                     │ project_rows               │
                     │ new_findings_by_project     │
                     │ evolution_rows              │
                     │ prioritized_findings        │
                     │ period, date_from, date_to  │
                     │ kev_hits                    │
                     └────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
      DocxGenerator    XlsxGenerator    PdfGenerator
      (python-docx)    (openpyxl)       (WeasyPrint +
                                         Jinja2)
              │               │               │
              └───────────────┴───────────────┘
                              │
                       ChartBuilder (matplotlib)
                       genera PNG en memoria (io.BytesIO)
                       → insertado en docx / html/pdf
```

**ReportGenerator port:**
```python
class ReportGenerator(Protocol):
    def generate(self, data: ReportData) -> bytes:
        ...
```

Cada generador implementa el protocolo. El caso de uso selecciona el generador adecuado según el formato solicitado.

**Secciones generadas (mapeadas desde spec.md §7.1):**

| # | Sección | docx | xlsx | pdf |
|---|---------|------|------|-----|
| 1 | Portada/encabezado | ✓ | Tab "Portada" | ✓ |
| 2 | Banner KPIs (4 cards) | ✓ | Celdas grandes col. A | ✓ |
| 3 | Párrafo ejecutivo (auto-generado) | ✓ | — | ✓ |
| 4 | Donut "Inventario vigente" | ✓ (PNG) | Chart nativo | ✓ (PNG) |
| 4 | Tabla heatmap estado actual | ✓ | Tab "Estado" | ✓ |
| 4 | Barra horizontal vigentes/proyecto | ✓ (PNG) | Chart nativo | ✓ (PNG) |
| 5 | Donut "Nuevas por gravedad" | ✓ (PNG) | Chart nativo | ✓ (PNG) |
| 5 | Tabla heatmap nuevas | ✓ | Tab "Nuevas" | ✓ |
| 5 | Barra horizontal ingresos/proyecto | ✓ (PNG) | Chart nativo | ✓ (PNG) |
| 6 | Barra divergente evolución | ✓ (PNG) | Chart nativo | ✓ (PNG) |
| 6 | Tabla evolución (inicio/actual/var/tratadas) | ✓ | Tab "Evolución" | ✓ |
| 7 | Conclusiones | ✓ | Tab "Resumen" | ✓ |
| 8 | Pie de firma | ✓ | — | ✓ |

---

## 9. Motor de priorización (dominio)

```python
# domain/services/prioritization.py
@dataclass(frozen=True)
class PriorityWeights:
    w_cvss: float = 0.30
    w_epss: float = 0.40
    w_kev: float = 0.30
    kev_minimum_score: float = 0.75

class PrioritizationService:
    def __init__(self, weights: PriorityWeights): ...

    def score(self, finding: Finding, is_in_kev: bool) -> PriorityScore:
        cvss_n = (finding.cvss_v3_base_score or 0.0) / 10.0
        epss   = finding.epss_score or 0.0
        kev    = 1.0 if is_in_kev else 0.0

        raw = (cvss_n * self.weights.w_cvss +
               epss   * self.weights.w_epss +
               kev    * self.weights.w_kev)

        clamped = min(max(raw, 0.0), 1.0)
        if is_in_kev:
            clamped = max(clamped, self.weights.kev_minimum_score)

        return PriorityScore(value=round(clamped * 100, 1), is_kev=is_in_kev)
```

---

## 10. Motor de recomendaciones de remediación

```python
# application/remediation/suggest_tasks.py
class RemediationAdvisor:
    """
    Genera tareas de remediación inteligentes basadas en:
    - Presencia en KEV (acción inmediata)
    - EPSS >= umbral alto (alta probabilidad de explotación)
    - Severidad Critical/High sin KEV
    - CVSS >= umbral configurado
    Actúa como experto en ciberseguridad + gerencia de proyectos.
    """

    def suggest(self, finding: Finding, is_in_kev: bool, score: PriorityScore) -> RemediationTask:
        if is_in_kev:
            return self._kev_task(finding, score)      # "Explotación activa confirmada"
        if (finding.epss_score or 0) >= self.config.epss_high_threshold:
            return self._high_epss_task(finding, score) # "Alta probabilidad 30 días"
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            return self._high_severity_task(finding, score)
        return self._standard_task(finding, score)
```

Cada tipo de tarea incluye: prioridad sugerida, acción recomendada (texto), fecha objetivo sugerida (KEV: 7 días; EPSS alto: 30 días; Critical: 60 días; High: 90 días).

---

## 11. Frontend web (Jinja2 + HTMX)

**Páginas principales:**

| Ruta | Plantilla | HTMX usado para |
|------|-----------|-----------------|
| `/` | `dashboard.html` | Auto-refresh estado sync cada 30s |
| `/projects` | `projects/list.html` | Filtro/ordenamiento sin recarga |
| `/projects/{uuid}` | `projects/detail.html` | Tabs findings / plan |
| `/reports` | `reports/generate.html` | Progreso de generación, descarga |
| `/prioritization` | `prioritization/index.html` | Filtros en tiempo real |
| `/kev` | `kev/index.html` | Botón "Actualizar KEV" con feedback |
| `/remediation` | `remediation/plan_list.html` | — |
| `/remediation/{id}` | `remediation/plan_detail.html` | Actualización de estado de tareas inline |
| `/settings` | `settings.html` | Test de conexión con feedback |

**Paleta UI:** Tailwind CSS via CDN (sin build step); mismos colores que el reporte de referencia para consistencia visual.

---

## 12. Despliegue

### Dockerfile
```dockerfile
FROM python:3.12-slim

# WeasyPrint requiere GTK/Pango
RUN apt-get update && apt-get install -y \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN pip install uv && uv sync --frozen --no-dev

COPY src/ src/
COPY alembic/ alembic/
COPY alembic.ini .

# Migraciones + arranque
CMD ["sh", "-c", "uv run alembic upgrade head && uv run uvicorn vulntrack.interfaces.web.main:app --host 0.0.0.0 --port 8000"]
```

### docker-compose.yml
```yaml
services:
  app:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data      # SQLite + archivos persistentes
    env_file: .env
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 5s
      retries: 3
```

`DATABASE_URL=sqlite+aiosqlite:////app/data/vulntrack.db` en `.env` → el archivo SQLite vive en el volumen montado.

---

## 13. Decisiones de arquitectura (ADRs)

### ADR-001 · Jinja2 + HTMX en lugar de SPA

**Decisión:** UI renderizada en servidor con Jinja2 e interactividad con HTMX.  
**Razón:** Sin build step, stack Python puro, complejidad suficiente para ~22 proyectos. HTMX cubre el 95% de las necesidades de interactividad (polling de sync, filtros, actualización inline de tareas). El puerto de API REST `/api/v1/` existe y puede servir una SPA futura sin refactoring.  
**Trade-off:** Menos potencia que React/Vue; aceptable para una herramienta interna local.

---

### ADR-002 · APScheduler in-process en lugar de Celery

**Decisión:** APScheduler corriendo en el mismo proceso FastAPI (lifespan).  
**Razón:** 22 proyectos, sync cada 6 horas = carga trivial. Celery requiere Redis/RabbitMQ como broker y un worker separado — complejidad desproporcionada para el volumen actual.  
**Ruta de migración:** Si el número de proyectos escala a >500 o se necesitan jobs distribuidos, reemplazar APScheduler por Celery cambiando únicamente `infrastructure/scheduler/`.

---

### ADR-003 · matplotlib para gráficas embebibles

**Decisión:** matplotlib genera los charts como PNG en memoria (BytesIO); se embeben en docx y pdf.  
**Razón:** plotly genera HTML/JS, incompatible con python-docx y WeasyPrint. matplotlib produce imágenes vectorizables con control total del estilo (colores exactos del reporte de referencia).  
**Trade-off:** Los charts del dashboard web usan chart.js vía CDN (más interactivo en browser); matplotlib solo para exports.

---

### ADR-004 · WeasyPrint para PDF

**Decisión:** WeasyPrint convierte HTML+CSS (plantillas Jinja2) a PDF.  
**Razón:** Reutiliza las plantillas web; el layout del PDF es mantenible en HTML/CSS. ReportLab requeriría construir el PDF programáticamente (mucho código de posicionamiento).  
**Trade-off:** WeasyPrint necesita librerías de sistema (GTK/Pango) → añadidas al Dockerfile. Funciona en Linux; en Windows solo dentro del contenedor Docker.

---

### ADR-005 · Puerto `TicketingPort` vacío para Jira/GLPI

**Decisión:** Definir el puerto en `domain/ports/ticketing_port.py` sin implementación concreta en el MVP.  
**Razón:** La spec confirma que la integración es post-MVP pero que "se deben dejar las bases". Definir el puerto ahora garantiza que el caso de uso `export_plan` ya depende de la abstracción correcta.  
**Implementación futura:** Crear `infrastructure/ticketing/jira_adapter.py` o `glpi_adapter.py` implementando el protocolo; cambiar la inyección de dependencias en `dependencies.py`.

---

### ADR-006 · SQLAlchemy async con SQLite

**Decisión:** `aiosqlite` + `SQLAlchemy 2.x async` en lugar de SQLModel o SQLAlchemy sync.  
**Razón:** FastAPI es async; un ORM síncrono bloquearía el event loop durante queries. SQLAlchemy async con `aiosqlite` mantiene la misma API y el switch a `asyncpg` (PostgreSQL) es trivial: solo cambia `DATABASE_URL`.  
**Nota:** `aiosqlite` no soporta `CHECK WAIT` ni `EXCLUSIVE` transactions de SQLite; aceptable para modo local single-user.

---

## 14. Calidad y desarrollo local

### pyproject.toml (extracto)
```toml
[tool.mypy]
strict = true
exclude = ["tests/", "alembic/"]

[tool.ruff]
target-version = "py312"
line-length = 100
select = ["E", "F", "I", "N", "UP", "S", "B", "A", "C4", "RUF"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

### .pre-commit-config.yaml
```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    hooks:
      - id: ruff
      - id: ruff-format
  - repo: https://github.com/pre-commit/mirrors-mypy
    hooks:
      - id: mypy
        args: ["--ignore-missing-imports"]
        files: "src/vulntrack/domain/|src/vulntrack/application/"
```

---

## 15. Checklist de completitud del plan

- [x] Arquitectura hexagonal con estructura de carpetas
- [x] Stack justificado con alternativas consideradas
- [x] Modelo de datos completo (entidades + tablas + índices)
- [x] Manejo de secretos (sin API key en BD)
- [x] Contratos de API interna
- [x] Estrategia de sincronización (paginación, reintentos, scheduler)
- [x] Arquitectura de generación de reportes (puerto + 3 adaptadores)
- [x] Motor de priorización (código de referencia)
- [x] Motor de recomendaciones de remediación
- [x] Frontend (Jinja2 + HTMX, Tailwind)
- [x] Despliegue (Dockerfile + docker-compose)
- [x] ADRs para decisiones no obvias
- [x] Configuración de calidad (mypy, ruff, pytest, pre-commit)
- [x] Puerto ticketera (vacío) para Jira/GLPI futuro
