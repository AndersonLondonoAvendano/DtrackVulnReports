# Tasks — VulnTrack Reports

> **Estado:** EN IMPLEMENTACIÓN  
> **Versión:** 1.1  
> **Fecha:** 2026-06-23  
> **Trazabilidad:** Desglosa plan.md v1.0. Cada tarea es ejecutable de forma autónoma.  
> **Estados:** `[ ]` Pendiente · `[~]` En curso · `[x]` Completado

---

## Convención

- Las dependencias listan los T-xxx que deben estar **Completados** antes de empezar.
- El **Definition of Done (DoD)** es el criterio objetivamente verificable de que la tarea terminó.
- Los tests se escriben **junto con** o **antes** del código de funcionalidad (P-03 de la constitution).

---

## GRUPO 0 · Andamiaje del proyecto

> **Objetivo:** Repositorio reproducible con toolchain configurado. Sin código de funcionalidad.

---

**[x] T-001 · Inicializar estructura del proyecto con uv**  
*Deps:* ninguna

Crear la estructura de carpetas definida en plan.md §3 y configurar `uv` como gestor de dependencias.

Acciones:
- Crear árbol de directorios: `src/vulntrack/{domain,application,infrastructure,interfaces}` + `tests/{domain,application,infrastructure,web}` + `alembic/versions/` + `docs/specs/`
- Crear `pyproject.toml` con metadatos del proyecto y dependencias principales (FastAPI, SQLAlchemy, httpx, pydantic-settings, alembic, aiosqlite, APScheduler, python-docx, openpyxl, matplotlib, WeasyPrint, structlog, tenacity)
- Crear `pyproject.toml` con dependencias de dev (pytest, pytest-asyncio, pytest-httpx, ruff, mypy, pre-commit, respx)
- Ejecutar `uv sync` y verificar que el entorno se crea sin errores
- Crear todos los `__init__.py` vacíos necesarios

**DoD:** `uv run python -c "import vulntrack"` pasa sin errores. Árbol de carpetas coincide exactamente con plan.md §3.

---

**[x] T-002 · Configurar ruff y mypy**  
*Deps:* T-001

Añadir configuración de calidad al `pyproject.toml`.

Acciones:
- Sección `[tool.ruff]`: target-version=py312, line-length=100, select=["E","F","I","N","UP","S","B","A","C4","RUF"]
- Sección `[tool.mypy]`: strict=true, exclude=["tests/","alembic/"], plugins=["pydantic.mypy"]
- Sección `[tool.pytest.ini_options]`: asyncio_mode="auto", testpaths=["tests"]
- Sección `[tool.coverage.run]`: source=["src/vulntrack"], omit=["*/migrations/*"]

**DoD:** `uv run ruff check src/` y `uv run mypy src/vulntrack/` pasan sin errores sobre el código vacío inicial.

---

**[x] T-003 · Configurar pre-commit hooks**  
*Deps:* T-002

Crear `.pre-commit-config.yaml` y activar hooks.

Acciones:
- Hooks: ruff, ruff-format, mypy (solo sobre `domain/` y `application/`), check-yaml, end-of-file-fixer, trailing-whitespace
- Ejecutar `uv run pre-commit install`
- Ejecutar `uv run pre-commit run --all-files` y verificar que pasa

**DoD:** `git commit` dispara los hooks automáticamente. `pre-commit run --all-files` pasa en verde.

---

**[x] T-004 · Configuración por entorno (pydantic-settings)**  
*Deps:* T-001

Crear el módulo de configuración y los archivos de entorno.

Acciones:
- Crear `src/vulntrack/config.py` con clase `Settings(BaseSettings)` según plan.md §5
- Crear `.env.example` con todas las variables y valores ficticios/descripción
- Crear `.env` local (gitignored) con valores de prueba apuntando a DT v4.14.1
- Agregar `.env` y `*.db` al `.gitignore`
- Singleton `get_settings()` con `lru_cache`

**DoD:** `Settings()` carga correctamente desde `.env`. `get_settings()` devuelve siempre la misma instancia. `DT_API_KEY` no aparece en `repr()` de la instancia (SecretStr).

---

**[x] T-005 · Logging estructurado**  
*Deps:* T-004

Configurar structlog para que toda la aplicación use logging estructurado.

Acciones:
- Crear `src/vulntrack/logging_config.py` con `configure_logging(level: str)` que configura structlog con salida JSON en producción y formato coloreado en desarrollo (`DEBUG=true`)
- Llamar a `configure_logging` al inicio del proceso (main.py lifespan)

**DoD:** `logger.info("evento", proyecto="test")` produce `{"event": "evento", "proyecto": "test", "level": "info", "timestamp": "..."}` en producción. Formato legible en dev.

---

**[x] T-006 · Setup de base de datos y Alembic**  
*Deps:* T-004

Configurar la conexión async a SQLite y el sistema de migraciones.

Acciones:
- Crear `src/vulntrack/infrastructure/persistence/database.py`:
  - `create_async_engine(settings.database_url, echo=settings.debug)`
  - `AsyncSessionLocal = async_sessionmaker(...)`
  - `get_session()` como dependency FastAPI (async generator)
- Crear `alembic.ini` con `script_location = alembic` y `sqlalchemy.url` leyendo de env
- Crear `alembic/env.py` configurado para async con aiosqlite
- Crear migration inicial vacía (sin tablas todavía; se añaden en T-031)

**DoD:** `uv run alembic upgrade head` ejecuta sin errores creando el archivo SQLite. `uv run alembic history` muestra la migración inicial.

---

**[x] T-007 · Dockerfile y docker-compose**  
*Deps:* T-004

Crear los artefactos de contenedorización.

Acciones:
- Crear `Dockerfile` multistage según plan.md §12 con GTK/Pango para WeasyPrint
- Crear `docker-compose.yml` con servicio `app`, volumen `./data:/app/data`, `env_file: .env`, healthcheck
- Crear `docker-compose.override.yml` para desarrollo (auto-reload con `--reload`, puerto expuesto)
- Verificar que `docker-compose build` completa sin errores

**DoD:** `docker-compose build` pasa sin errores. La imagen tiene Python 3.12 y WeasyPrint instalados (`docker run ... python -c "import weasyprint"`).

---

**[x] T-008 · FastAPI app esqueleto + healthcheck**  
*Deps:* T-005, T-006

Crear la aplicación FastAPI mínima con lifespan y healthcheck.

Acciones:
- Crear `src/vulntrack/interfaces/web/main.py`:
  - `create_app()` factory (facilita tests)
  - `lifespan` que llama `configure_logging`, inicia scheduler (stub), ejecuta migraciones pendientes
  - `GET /health` → `{"status": "ok", "db": "ok"}`
  - Incluir CORS con `settings.allowed_origins`
  - Montar archivos estáticos en `/static`
- Crear `src/vulntrack/interfaces/web/dependencies.py` con stubs iniciales

**DoD:** `uv run uvicorn vulntrack.interfaces.web.main:app` arranca sin errores. `GET /health` devuelve 200 `{"status": "ok"}`. `GET /docs` muestra OpenAPI UI.

---

## GRUPO 1 · Capa de dominio

> **Objetivo:** Modelar el negocio. Sin framework, sin DB. Completamente testeable en aislamiento.

---

**[x] T-011 · Value objects: Severity y PriorityScore**  
*Deps:* T-001

Crear los value objects fundamentales del dominio.

Acciones:
- `domain/value_objects/severity.py`: `Severity(str, Enum)` con valores CRITICAL/HIGH/MEDIUM/LOW/UNASSIGNED; métodos `weight() -> float` (Critical=1.0, High=0.75, Medium=0.5, Low=0.25, Unassigned=0.1) y `color_hex() -> str` (paleta del reporte de referencia)
- `domain/value_objects/priority_score.py`: `@dataclass(frozen=True) PriorityScore` con `value: float` (0–100), `band: PriorityBand` (IMMEDIATE/HIGH/MEDIUM/LOW), `is_kev: bool`, `breakdown: dict[str, float]`; `PriorityBand` enum con rangos 75+/50-74/25-49/0-24
- Tests unitarios para `Severity.weight()`, `PriorityScore` con distintos valores

**DoD:** `ruff`, `mypy` pasan. Tests en `tests/domain/test_value_objects.py` pasan con cobertura 100% de las clases.

---

**[x] T-012 · Value objects: DateRange y ReportPeriod**  
*Deps:* T-011

Crear los value objects de tiempo.

Acciones:
- `domain/value_objects/date_range.py`: `@dataclass(frozen=True) DateRange(date_from: date, date_to: date)` con validación `date_from <= date_to` en `__post_init__` (lanza `DomainError`); método `days() -> int`
- `domain/value_objects/report_period.py`: `ReportPeriod(str, Enum)` WEEKLY/MONTHLY/QUARTERLY/CUSTOM; `@staticmethod resolve(period, year, quarter, date_from, date_to) -> DateRange`
- Tests: DateRange inválido lanza excepción; `resolve(QUARTERLY, 2026, "Q2")` devuelve `DateRange(2026-04-01, 2026-06-30)`

**DoD:** Tests en `tests/domain/test_value_objects.py` pasan incluyendo casos límite (mismo día inicio=fin, Q1/Q2/Q3/Q4).

---

**[x] T-013 · Entidades de dominio: Project y MetricSnapshot**  
*Deps:* T-011

Acciones:
- `domain/entities/project.py`: `@dataclass Project` según plan.md §4.1
- `domain/entities/metric_snapshot.py`: `@dataclass MetricSnapshot` con `SnapshotSource(str, Enum)` DT_CURRENT/DT_HISTORICAL/LOCAL; método `total_assigned() -> int` (critical+high+medium+low)
- `domain/exceptions.py`: `DomainError`, `ProjectNotFoundError`, `SnapshotNotAvailableError`

**DoD:** Dataclasses instanciables sin importar ninguna biblioteca externa. `mypy --strict` pasa.

---

**[x] T-014 · Entidad de dominio: Finding**  
*Deps:* T-013

Acciones:
- `domain/entities/finding.py`: `@dataclass Finding` según plan.md §4.1
- Método `normalized_cvss() -> float`: `(cvss_v3_base_score or 0.0) / 10.0`
- Método `safe_epss() -> float`: `epss_score or 0.0`

**DoD:** `mypy --strict` pasa. Tests básicos de instanciación y métodos.

---

**[x] T-015 · Entidades de dominio: KevEntry y Remediación**  
*Deps:* T-013

Acciones:
- `domain/entities/kev_entry.py`: `@dataclass KevEntry` según plan.md §4.1
- `domain/entities/remediation.py`: `@dataclass RemediationPlan` y `@dataclass RemediationTask` con `TaskStatus(str, Enum)` PENDING/IN_PROGRESS/COMPLETED/DISCARDED y `PriorityBand` importado de value_objects
- Método `RemediationTask.is_overdue(today: date) -> bool`

**DoD:** `mypy --strict` pasa. Test de `is_overdue()` con fecha pasada, futura y nula.

---

**[x] T-016 · Puertos (interfaces de dominio)**  
*Deps:* T-013, T-014, T-015

Crear todas las interfaces (ABC/Protocol) que separan dominio de infraestructura.

Acciones en `domain/ports/`:
- `dt_client.py`: `class DtClientPort(Protocol)` con métodos `get_projects`, `get_project_metrics`, `get_project_findings`, `get_project_metric_history`, `get_server_version`
- `project_repository.py`: `upsert`, `get_by_uuid`, `list_all`, `count`
- `finding_repository.py`: `upsert_batch`, `list_by_project`, `list_all_active`, `get_new_in_range`
- `snapshot_repository.py`: `upsert`, `get_closest_before`, `get_closest_after`, `list_by_project_in_range`
- `remediation_repository.py`: `create_plan`, `get_plan`, `list_plans_by_project`, `create_task`, `update_task`, `list_tasks_by_plan`
- `kev_repository.py`: `upsert_batch`, `get_by_cve_id`, `is_cve_in_kev`, `list_all`, `get_catalog_meta`, `update_catalog_meta`
- `report_generator.py`: `class ReportGenerator(Protocol)` con `generate(data: ReportData) -> bytes`
- `ticketing_port.py`: `class TicketingPort(Protocol)` con `create_ticket`, `update_ticket` — métodos con cuerpo `...` (para implementación futura)

**DoD:** Todos los puertos son `Protocol` o `ABC`. Ninguno importa SQLAlchemy, httpx ni FastAPI. `mypy --strict` pasa.

---

**[x] T-017 · Servicio de dominio: PrioritizationService**  
*Deps:* T-014, T-016

Implementar la fórmula de priorización según plan.md §9 y spec.md §5/HU-502.

Acciones:
- `domain/services/prioritization.py`:
  - `@dataclass(frozen=True) PriorityWeights` con valores por defecto (w_cvss=0.30, w_epss=0.40, w_kev=0.30, kev_minimum=0.75)
  - `class PrioritizationService` con `score(finding, is_in_kev) -> PriorityScore`
  - Implementar fórmula exacta de plan.md §9 con regla de elevación KEV
- Tests en `tests/domain/test_prioritization.py`:
  - CVE en KEV con CVSS=9.8, EPSS=0.85 → score ≈ 92.8, band=IMMEDIATE
  - CVE en KEV con CVSS=2.0, EPSS=0.01 → score=75 (elevación mínima), band=IMMEDIATE
  - CVSS=None, EPSS=None, no KEV → score=0, band=LOW
  - Pesos personalizados recalculan correctamente
  - EPSS=None tratado como 0.0

**DoD:** 100% cobertura de `prioritization.py`. Todos los casos del HU-502 Given/When/Then verificados.

---

**[x] T-018 · Servicio de dominio: AdvanceCalculator**  
*Deps:* T-013, T-016

Calcular nuevas y tratadas por severidad para un rango de fechas.

Acciones:
- `domain/services/advance_calculator.py`:
  - `@dataclass AdvanceResult` con `project_uuid`, `inicio: MetricSnapshot | None`, `actual: MetricSnapshot | None`, `variacion_total: int`, `tratadas: int` (max(0, -variacion_total)), `nuevas_por_severidad: dict[Severity, int]`
  - `class AdvanceCalculator` con `calculate(project, inicio_snapshot, actual_snapshot, new_findings) -> AdvanceResult`
  - Lógica: tratadas = max(0, inicio.total - actual.total); nuevas = findings con attributed_on en rango
- Tests:
  - Proyecto que mejoró (inicio=20, actual=8) → tratadas=12
  - Proyecto que empeoró (inicio=5, actual=11) → tratadas=0, variacion=+6
  - Sin snapshot de inicio → `SnapshotNotAvailableError`

**DoD:** Tests Given/When/Then del HU-401 y HU-402 pasan. `mypy --strict` pasa.

---

**[x] T-019 · Servicio de dominio: KevMatcher**  
*Deps:* T-014, T-015, T-016

Cruzar hallazgos con el catálogo KEV.

Acciones:
- `domain/services/kev_matcher.py`:
  - `class KevMatcher` que recibe una colección de `KevEntry` y expone `is_in_kev(vuln_id: str) -> bool` y `get_kev_details(vuln_id: str) -> KevEntry | None`
  - Usa un `dict[str, KevEntry]` indexado por `cve_id` para lookup O(1)
- Tests: CVE presente, CVE ausente, CVE con capitalización mixta (normalizar a uppercase)

**DoD:** Lookup O(1) verificado. Tests con >1000 entradas mockeadas pasan en <1ms.

---

## GRUPO 2 · Infraestructura — Persistencia

> **Objetivo:** Modelos ORM, migraciones Alembic, implementaciones de todos los repositorios.

---

**[x] T-031 · Modelos ORM y migración inicial**  
*Deps:* T-006, T-013, T-014, T-015

Crear los modelos SQLAlchemy y la migración que los define.

Acciones:
- `infrastructure/persistence/orm_models.py`: `Base = DeclarativeBase()` con las 8 tablas del plan.md §4.2 (projects, findings, metric_snapshots, kev_entries, remediation_plans, remediation_tasks, app_settings)
- Añadir índices críticos del plan.md §4.2
- Crear migración Alembic `0001_initial_schema.py` con `op.create_table(...)` para todas las tablas
- `uv run alembic upgrade head` crea el schema completo

**DoD:** `alembic upgrade head` crea todas las tablas. `alembic downgrade -1` las elimina limpiamente. `alembic upgrade head` nuevamente funciona (idempotente en el flujo upgrade/downgrade).

---

**[x] T-032 · Repositorio: ProjectRepository**  
*Deps:* T-031, T-016

Acciones:
- `infrastructure/persistence/repositories/project_repo.py`: `SqliteProjectRepository` implementando `ProjectRepository` port
- Métodos: `upsert(project: Project)`, `get_by_uuid(uuid: str) -> Project | None`, `list_all() -> list[Project]`, `count() -> int`
- Tests en `tests/infrastructure/test_repositories.py` usando SQLite en memoria (fixture en conftest.py)

**DoD:** Tests de upsert idempotente (insertar el mismo proyecto dos veces → 1 registro), `list_all` ordena por nombre, `get_by_uuid` devuelve None si no existe.

---

**[x] T-033 · Repositorio: FindingRepository**  
*Deps:* T-031, T-016

Acciones:
- `SqliteFindingRepository` con métodos: `upsert_batch(findings: list[Finding])`, `list_by_project(project_uuid, suppress_suppressed=True) -> list[Finding]`, `list_all_active() -> list[Finding]`, `get_new_in_range(date_from, date_to) -> list[Finding]`
- Tests: upsert_batch con 100 findings, `get_new_in_range` con attributed_on dentro y fuera del rango

**DoD:** `get_new_in_range` usa índice `attributed_on` (verificar con EXPLAIN QUERY PLAN). Tests pasan.

---

**[x] T-034 · Repositorio: SnapshotRepository**  
*Deps:* T-031, T-016

Acciones:
- `SqliteSnapshotRepository` con: `upsert(snapshot)`, `get_closest_before(project_uuid, date) -> MetricSnapshot | None`, `get_closest_after(project_uuid, date) -> MetricSnapshot | None`, `list_by_project_in_range(project_uuid, date_from, date_to) -> list[MetricSnapshot]`
- Tests: snapshot más cercano antes de una fecha cuando hay múltiples candidatos; retorna None si no hay ninguno

**DoD:** `get_closest_before` usa `ORDER BY snapshot_date DESC LIMIT 1`. Tests pasan.

---

**[x] T-035 · Repositorios: KevRepository y RemediationRepository**  
*Deps:* T-031, T-016

Acciones:
- `SqliteKevRepository`: `upsert_batch(entries: list[KevEntry])`, `get_by_cve_id(cve_id: str) -> KevEntry | None`, `is_cve_in_kev(cve_id: str) -> bool`, `list_all() -> list[KevEntry]`, `get_catalog_meta() -> KevCatalogMeta | None`, `update_catalog_meta(...)`
- `SqliteRemediationRepository`: `create_plan`, `get_plan`, `list_plans_by_project`, `create_task`, `update_task(task_id, **fields)`, `list_tasks_by_plan`
- Tests para ambos repositorios

**DoD:** `is_cve_in_kev` hace SELECT COUNT(1) (no trae el objeto completo). Tests pasan.

---

**[x] T-036 · Repositorio: AppSettingsRepository y singleton**  
*Deps:* T-031

Acciones:
- Tabla `app_settings` usa `id=1` como singleton
- `SqliteAppSettingsRepository`: `get() -> AppSettings`, `update(**fields) -> AppSettings`; si no existe fila, `get()` la crea con valores por defecto
- `AppSettings` dataclass con todos los campos de plan.md §4.2 (`app_settings`)

**DoD:** `get()` llamado en base vacía crea la fila con defaults. Segundo `get()` devuelve la misma fila.

---

## GRUPO 3 · Infraestructura — Clientes externos

---

**[x] T-041 · Modelos de respuesta de DT (Pydantic)**  
*Deps:* T-013, T-014

Crear los modelos Pydantic que representan exactamente la respuesta de la API de DT.

Acciones en `infrastructure/dt/response_models.py`:
- `DtProject`: campos name, uuid, version, description, lastBomImport
- `DtMetrics`: critical, high, medium, low, unassigned, riskScore, total
- `DtFinding`: component (name, version, group), vulnerability (vulnId, source, severity, cvssV3BaseScore, epssScore, epssPercentile, attributedOn), isSuppressed
- `DtVulnerability`: para endpoint `/api/v1/vulnerability/project/{uuid}` (alternativa a findings)
- Usar `model_config = ConfigDict(populate_by_name=True)` para manejar camelCase de DT

**DoD:** `DtProject.model_validate(json_raw)` funciona con respuesta real de DT v4.14.1 (usando fixture con JSON guardado de la instancia de prueba). `mypy --strict` pasa.

---

**[x] T-042 · Cliente HTTP de Dependency-Track**  
*Deps:* T-041, T-016, T-004

Implementar `DtHttpClient` que implementa `DtClientPort`.

Acciones en `infrastructure/dt/client.py`:
- Constructor recibe `base_url: str`, `api_key: str`, `semaphore: asyncio.Semaphore(5)`
- Todos los métodos son `async`; usan `httpx.AsyncClient` con header `X-Api-Key`
- `get_projects(page=1, page_size=100) -> tuple[list[DtProject], int]` (devuelve lista + X-Total-Count)
- `get_all_projects() -> list[DtProject]` — itera páginas automáticamente
- `get_project_metrics(uuid: str) -> DtMetrics`
- `get_project_findings(uuid: str) -> list[DtFinding]`
- `get_project_metric_history(uuid: str, days: int) -> list[DtMetrics]`
- `get_server_version() -> str` — llama a `/api/v1/about`
- Reintentos con tenacity: 3 intentos, backoff exponencial 2–30s, solo en 5xx y timeout

**DoD:** Tests en `tests/infrastructure/test_dt_client.py` usando `respx` para mockear httpx. Casos: paginación (3 páginas de 100), error 401 no se reintenta, error 503 se reintenta 3 veces. `mypy --strict` pasa.

---

**[x] T-043 · Cliente CISA KEV**  
*Deps:* T-015, T-004

Acciones en `infrastructure/kev/cisa_kev_client.py`:
- `CisaKevClient` con `async fetch() -> list[KevEntry]`
- Descarga el JSON de CISA (URL configurable pero con default hardcodeado como constante — NO como URL construida dinámicamente de input de usuario)
- Parsea `vulnerabilities` → `list[KevEntry]`
- Timeout de 30 segundos; lanza `KevFetchError` en fallo de red

**DoD:** Test con respx mockeando la URL de CISA; fixture con un JSON de ejemplo de 5 entradas. Verifica que `dateAdded` se parsea correctamente como `date`. `mypy --strict` pasa.

---

## GRUPO 4 · Infraestructura — Generadores de reportes

> **Objetivo:** Cada generador recibe un `ReportData` puro y devuelve `bytes`. Cero dependencias de BD o DT.

---

**[x] T-051 · ReportData y ChartBuilder**  
*Deps:* T-013, T-014, T-015, T-018

Acciones:
- `infrastructure/reports/chart_builder.py`:
  - `@dataclass ReportData` con todos los campos que necesitan los generadores (portfolio_metrics, project_rows, new_findings_by_project, evolution_rows, prioritized_findings, kev_hits, period_label, date_from, date_to, generated_at, author)
  - `@dataclass ProjectRow`: name, critical, high, medium, low, unassigned, total, risk_score
  - `@dataclass EvolutionRow`: name, inicio, actual, variacion, tratadas
  - `class ChartBuilder` con métodos que devuelven `io.BytesIO`:
    - `donut_by_severity(counts: dict[Severity, int], title: str) -> BytesIO` — donut con total en centro, colores del reporte de referencia
    - `horizontal_bars_by_project(rows: list[ProjectRow], title: str) -> BytesIO` — barras horizontales con valor al final
    - `divergent_bars_evolution(rows: list[EvolutionRow], title: str) -> BytesIO` — verde izq. / rojo der.
    - `grouped_bars_inicio_vs_actual(rows: list[EvolutionRow], title: str) -> BytesIO` — azul inicio / rojo actual
- Tests: cada método produce bytes PNG > 0 con datos de prueba; no lanza excepción con proyecto sin vulnerabilidades (todos ceros)

**DoD:** `ChartBuilder` no importa FastAPI, SQLAlchemy ni httpx. Tests pasan. Imágenes visualmente correctas (verificadas manualmente una vez).

---

**[x] T-052 · Generador Word (.docx)**  
*Deps:* T-051, T-016

Acciones en `infrastructure/reports/docx_generator.py`:
- `DocxGenerator` implementa `ReportGenerator` port
- `generate(data: ReportData) -> bytes`
- Implementar todas las secciones de spec.md §7.1 en orden:
  1. Encabezado (título, período, fuente, autor)
  2. Banner 4 KPIs (tabla 1×4 con texto grande y coloreado)
  3. Párrafo ejecutivo (generado con f-string desde los datos)
  4. Estado actual: donut PNG + tabla heatmap + barra PNG
  5. Nuevas en el período: donut PNG + tabla heatmap + barra PNG
  6. Evolución: divergente PNG + tabla inicio/actual/variacion/tratadas
  7. Conclusiones (bullet list auto-generado con las top 3 observaciones)
  8. Pie de firma (tabla 3 columnas: Elaboró/Revisó/Aprobó)
- Colores de heatmap según spec.md §7.2
- Encabezados de tabla en azul marino (#1F3864) con texto blanco

**DoD:** `generate(sample_report_data)` devuelve bytes que `python-docx` puede re-abrir sin error. El .docx generado con datos del Q2 2026 del reporte de referencia produce visualmente el mismo contenido. Test de integración guarda el archivo y lo reabre.

---

**[x] T-053 · Generador Excel (.xlsx)**  
*Deps:* T-051, T-016

Acciones en `infrastructure/reports/xlsx_generator.py`:
- `XlsxGenerator` implementa `ReportGenerator` port
- Hojas: "Resumen" (KPIs), "Estado" (heatmap vigentes), "Nuevas" (heatmap nuevas), "Evolución" (tabla + chart nativo), "Hallazgos Priorizados" (tabla con score)
- Heatmap de colores con `openpyxl.styles.PatternFill` según paleta de referencia
- Charts nativos de openpyxl (donut + barras) en las hojas correspondientes
- Congelar primera fila en tablas (`freeze_panes`)
- Autowidth en columnas de texto

**DoD:** Archivo .xlsx abre sin error en Excel/LibreOffice. Las celdas de severidad tienen el color correcto. Test guarda y relee con openpyxl verificando valores de celda.

---

**[x] T-054 · Generador PDF (WeasyPrint + Jinja2)**  
*Deps:* T-051, T-016

Acciones en `infrastructure/reports/pdf_generator.py`:
- `PdfGenerator` implementa `ReportGenerator` port
- Plantilla Jinja2 `templates/reports/report_pdf.html` con CSS inline/embebido:
  - Misma estructura de secciones que el .docx
  - Charts como `<img src="data:image/png;base64,...">` (base64 de BytesIO)
  - Tabla heatmap con colores CSS
  - `@page` CSS para tamaño A4, márgenes 2cm
- `WeasyPrint.HTML(string=html).write_pdf() -> bytes`

**DoD:** PDF generado tiene el tamaño correcto (A4), las imágenes de gráficas se renderizan, los colores del heatmap son correctos. Test guarda el PDF y verifica que es bytes válidos (empieza con `%PDF`).

---

## GRUPO 5 · Capa de aplicación

> **Objetivo:** Casos de uso que orquestan dominio + puertos. Sin framework, sin BD concreta.

---

**[x] T-061 · Caso de uso: SyncPortfolio**  
*Deps:* T-016, T-017, T-032, T-033, T-034

Acciones en `application/sync/sync_portfolio.py`:
- `@dataclass SyncResult`: synced_projects, failed_projects, new_snapshots, duration_seconds
- `class SyncPortfolioUseCase`:
  - `__init__(dt_client, project_repo, finding_repo, snapshot_repo, settings_repo)`
  - `async execute() -> SyncResult`
  - Implementar algoritmo de sync del plan.md §7.1
  - Backfill histórico solo si `snapshot_repo.count_by_source(DT_HISTORICAL) == 0`
- Tests con todos los puertos mockeados:
  - Sync con 3 proyectos, todos exitosos
  - Sync con 1 proyecto que falla → continúa con los otros, fallo registrado en resultado
  - Idempotencia: sync dos veces consecutivas no duplica datos

**DoD:** Tests pasan. `SyncPortfolioUseCase` no importa SQLAlchemy, httpx ni FastAPI.

---

**[x] T-062 · Caso de uso: SyncKev**  
*Deps:* T-016, T-035, T-043

Acciones en `application/sync/sync_kev.py`:
- `class SyncKevUseCase` con `async execute() -> KevSyncResult` (entries_added, entries_updated, catalog_date)
- Tests: KEV vacío → batch upsert con N entradas; KEV existente → solo actualiza las modificadas

**DoD:** Tests con KEV client mockeado. `mypy --strict` pasa.

---

**[x] T-063 · Queries: DashboardQuery**  
*Deps:* T-032, T-033, T-034, T-035, T-036

Acciones en `application/queries/dashboard_query.py`:
- `@dataclass DashboardData`: total_vigentes, vigentes_por_severidad, proyectos_en_cero, proyectos_con_criticas, last_sync_at, kev_hits_count, tasks_summary
- `class DashboardQuery` con `execute() -> DashboardData`
- Tests con repos mockeados devolviendo datos del reporte Q2 2026

**DoD:** `DashboardData` cubre todos los campos del HU-201. Tests pasan.

---

**[x] T-064 · Queries: ProjectDetailQuery y PrioritizedFindingsQuery**  
*Deps:* T-017, T-033, T-035

Acciones:
- `application/queries/project_detail_query.py`: devuelve proyecto + findings priorizados + snapshot actual + plan de trabajo
- `application/queries/prioritized_findings_query.py`: devuelve todos los findings del portafolio ordenados por `PriorityScore` DESC; soporta filtro `kev_only=True` y filtros de umbrales CVSS/EPSS
- Tests con datos del Q2 2026: verificar orden correcto de hallazgos

**DoD:** Finding con KEV aparece primero. Tests pasan.

---

**[x] T-065 · Caso de uso: BuildReportData**  
*Deps:* T-018, T-019, T-063, T-064

Acciones en `application/reports/build_report_data.py`:
- `class BuildReportDataUseCase` con `execute(report_type, date_range, project_uuids=None) -> ReportData`
- Ensambla `ReportData` usando `AdvanceCalculator`, `KevMatcher`, `PrioritizationService`
- Tests: `ReportData` con datos del Q2 2026 — verificar que vigentes=223, nuevas=118, tratadas=97 (usando fixtures con snapshots reales del reporte)

**DoD:** Tests con datos del Q2 2026 de referencia producen los KPIs exactos del reporte. `mypy --strict` pasa.

---

**[x] T-066 · Casos de uso: GeneratePortfolioReport y GenerateProjectReport**  
*Deps:* T-052, T-053, T-054, T-065

Acciones:
- `application/reports/generate_portfolio_report.py`: `GeneratePortfolioReportUseCase` que llama a `BuildReportData` y luego al `ReportGenerator` correspondiente según formato
- `application/reports/generate_project_report.py`: igual pero filtrando por un proyecto
- Soporte para múltiples formatos simultáneos → devuelve `dict[ReportFormat, bytes]`
- Tests: smoke test que genera .docx con datos mock y verifica que el resultado > 0 bytes

**DoD:** Tests pasan. Los casos de uso no conocen python-docx, openpyxl ni WeasyPrint directamente.

---

**[x] T-067 · Casos de uso: Remediación inteligente**  
*Deps:* T-017, T-019, T-035

Acciones en `application/remediation/`:
- `create_plan.py`: `CreatePlanUseCase.execute(project_uuid, name, description) -> RemediationPlan`
- `update_task.py`: `UpdateTaskUseCase.execute(task_id, status, assignee, notes, target_date) -> RemediationTask`; valida transiciones de estado válidas (no puede pasar de COMPLETED a PENDING)
- `suggest_tasks.py`: `SuggestTasksUseCase.execute(plan_id) -> list[RemediationTask]` — implementa el `RemediationAdvisor` de plan.md §10 con fechas objetivo por tipo (KEV: +7d, EPSS alto: +30d, Critical: +60d, High: +90d)
- `export_plan.py`: `ExportPlanUseCase.execute(plan_id, format) -> bytes` — genera .xlsx o .pdf del plan

**DoD:** Tests en `tests/application/test_suggest_tasks.py`: finding KEV → tarea con recommended_action "Explotación activa confirmada" y target_date = hoy + 7 días. Test de transición de estado inválida lanza excepción.

---

## GRUPO 6 · Interfaz web

> **Objetivo:** Conectar los casos de uso al mundo exterior via FastAPI. Cada router es delgado.

---

**[x] T-071 · Schemas (DTOs) y sistema de inyección de dependencias**  
*Deps:* T-008, T-032 a T-036, T-041, T-043

Acciones:
- `interfaces/web/schemas/`: crear todos los Pydantic schemas de request/response para todos los endpoints del plan.md §6
- `interfaces/web/dependencies.py`: funciones `get_db_session()`, `get_dt_client()`, `get_sync_use_case()`, `get_report_use_case()`, etc. — fábrica de instancias con inyección de settings
- Tests básicos de schemas: serialización/deserialización de casos del spec

**DoD:** Los schemas importan solo Pydantic y entidades de dominio. `mypy --strict` pasa.

---

**[x] T-072 · Scheduler (APScheduler)**  
*Deps:* T-061, T-062, T-008

Acciones en `infrastructure/scheduler/apscheduler_setup.py`:
- `setup_scheduler(app: FastAPI, settings: Settings)` añadido al lifespan de `main.py`
- Job 1: `sync_portfolio_job` — interval `settings.sync_interval_hours` horas
- Job 2: `daily_snapshot_job` — cron 01:00 UTC (fuerza un snapshot aunque ya haya sync del día)
- Manejo de errores: exception en job → log estructurado con nivel ERROR, no detiene el scheduler

**DoD:** Al iniciar la app, los jobs aparecen en `scheduler.get_jobs()`. Test de integración con APScheduler en modo `coalesce=True`.

---

**[x] T-073 · Router: Sync + Dashboard**  
*Deps:* T-061, T-063, T-071, T-072

Acciones:
- `routers/sync.py`: `POST /api/v1/sync/run` (BackgroundTask) + `GET /api/v1/sync/status`
- `routers/dashboard.py`: `GET /api/v1/dashboard` (JSON) + `GET /` (HTML con Jinja2)
- Template `templates/dashboard.html`: banner 4 KPIs (colores del reporte de referencia), tabla top proyectos por riesgo, estado de sincronización con HTMX polling cada 30s, botón "Sincronizar ahora"
- Tests con `TestClient`: `POST /api/v1/sync/run` devuelve 202; `GET /api/v1/dashboard` devuelve JSON con campos esperados

**DoD:** La página `/` carga en el browser con datos sincronizados. El polling de sync status actualiza el indicador sin recargar la página.

---

**[x] T-074 · Router: Proyectos**  
*Deps:* T-064, T-071

Acciones:
- `routers/projects.py`: `GET /api/v1/projects` (paginado, ?sort=&order=&search=) + `GET /api/v1/projects/{uuid}` + rutas HTML `/projects` y `/projects/{uuid}`
- Templates: `projects/list.html` con tabla ordenable/filtrable via HTMX, `projects/detail.html` con tabs (Métricas / Hallazgos / Plan de trabajo)
- Tests: sort por critical DESC, search por nombre

**DoD:** La tabla se ordena y filtra sin recargar la página completa. El detalle de proyecto muestra hallazgos priorizados.

---

**[x] T-075 · Router: Reportes**  
*Deps:* T-066, T-071

Acciones:
- `routers/reports.py`: `POST /api/v1/reports/generate` → `StreamingResponse` (un formato) o `StreamingResponse` con ZIP (múltiples)
- Ruta HTML `/reports` con formulario: selector de tipo, período (dropdown Semanal/Mensual/Trimestral + selector Q/año + campos custom), checkbox proyectos, checkbox formatos
- HTMX: al submit, spinner de "Generando..." y luego descarga automática del archivo
- Tests: `POST /api/v1/reports/generate {type=portfolio, period=quarterly, quarter=Q2, year=2026, formats=[xlsx]}` con datos mock → 200 y Content-Disposition con nombre de archivo correcto

**DoD:** Desde el browser se puede generar y descargar el reporte en los 3 formatos. El nombre del archivo sigue el patrón `Reporte_Portafolio_2026-Q2.xlsx`.

---

**[x] T-076 · Router: Priorización**  
*Deps:* T-064, T-071

Acciones:
- `routers/prioritization.py`: `GET /api/v1/findings/prioritized` (JSON) + `GET /api/v1/findings/thresholds` + ruta HTML `/prioritization`
- Template: tabla de findings con columnas CVE/Proyecto/Severidad/CVSS/EPSS/KEV/Score, filtro "solo KEV", filtros de umbral CVSS y EPSS (HTMX), badges de color por banda de prioridad
- Tests: filtro `kev_only=true` devuelve solo findings en KEV

**DoD:** Findings KEV aparecen en rojo/inmediata. El filtro funciona sin recargar.

---

**[x] T-077 · Router: KEV**  
*Deps:* T-062, T-071

Acciones:
- `routers/kev.py`: `GET /api/v1/kev/status`, `POST /api/v1/kev/refresh` (BackgroundTask) + `GET /api/v1/kev/findings` + ruta HTML `/kev`
- Template `/kev`: estado del catálogo (fecha, N entradas, días desde última actualización), aviso si >7 días con botón "Actualizar KEV", tabla de findings afectados con columnas CVE/Componente/Proyecto/Descripción KEV/Fecha adición/Acción requerida
- Tests: `POST /api/v1/kev/refresh` devuelve 202; `GET /api/v1/kev/status` con catálogo de 10 días → campo `is_stale: true`

**DoD:** Botón "Actualizar KEV" muestra spinner, luego actualiza el estado sin recargar la página.

---

**[x] T-078 · Router: Remediación**  
*Deps:* T-067, T-071

Acciones:
- `routers/remediation.py`: todos los endpoints del plan.md §6 (CRUD de planes y tareas + suggest + export)
- Templates: `/remediation` lista de planes por proyecto; `/remediation/{id}` detalle con tabla de tareas (status editable inline con HTMX), botón "Generar sugerencias automáticas", botón "Exportar plan"
- Tests: `POST /api/v1/remediation/plans/{id}/suggest` crea tareas; `PATCH /api/v1/remediation/tasks/{id}` actualiza status; `POST /api/v1/remediation/plans/{id}/export` devuelve .xlsx

**DoD:** El analista puede crear un plan, generar sugerencias automáticas, cambiar el estado de tareas inline, y exportar el plan en .xlsx.

---

**[x] T-079 · Router: Configuración**  
*Deps:* T-036, T-042, T-071

Acciones:
- `routers/config.py`: `GET /api/v1/config`, `PATCH /api/v1/config`, `POST /api/v1/config/test-connection` + ruta HTML `/settings`
- Template: formulario con URL de DT, campo API Key (enmascarado), intervalo sync, umbrales, pesos de priorización; botón "Probar conexión" con HTMX que muestra resultado en tiempo real
- Tests: `POST /api/v1/config/test-connection` con DT mockeado → `{ok: true, dt_version: "4.14.1"}`

**DoD:** El analista puede cambiar los pesos de priorización desde la UI y ver el efecto en la lista de priorización. La API Key nunca aparece en claro en la respuesta JSON.

---

## GRUPO 7 · Integración y cierre

---

**[x] T-081 · Healthcheck completo**  
*Deps:* T-008, T-042

Ampliar el healthcheck básico de T-008.

Acciones:
- `GET /health` verifica: conexión BD (simple SELECT 1), versión DT (opcional, timeout 2s), versión de la app (desde `pyproject.toml`)
- Respuesta: `{status: "ok"|"degraded", db: "ok"|"error", dt_reachable: true|false, app_version: "x.y.z"}`
- Si la BD no responde → status 503

**DoD:** `GET /health` devuelve 200 con app operativa y 503 si la BD no está disponible.

---

**[x] T-082 · Pruebas de integración end-to-end**  
*Deps:* todos los T-07x

Acciones en `tests/web/test_e2e.py`:
- Setup: base SQLite en memoria con fixtures del Q2 2026 (proyectos, findings, snapshots, KEV)
- Tests E2E:
  - Generar reporte .xlsx del Q2 2026 → verificar KPIs exactos (vigentes=223, nuevas=118, tratadas=97)
  - Listar proyectos priorizados → daviplata-webview-frontend aparece primero (mayor riesgo)
  - Crear plan, generar sugerencias → hallazgos KEV tienen target_date = hoy+7d
  - Exportar plan → archivo .xlsx con columnas correctas

**DoD:** Todos los tests E2E pasan en CI (sin red, sin DT real). Cobertura total dominio+aplicación ≥ 80%.

---

**[x] T-083 · README y documentación de uso**  
*Deps:* T-081

Crear `README.md` con:
1. Requisitos previos (Docker, Docker Compose v2)
2. Configuración (copiar `.env.example` a `.env`, rellenar DT_BASE_URL y DT_API_KEY)
3. Arranque: `docker-compose up --build`
4. Primera sincronización: instrucciones
5. Generación de primer reporte: instrucciones
6. Estructura del proyecto (referencia a plan.md)
7. Comandos de desarrollo (`uv sync`, `pytest`, `ruff`, `mypy`, `alembic upgrade head`)

**DoD:** Un compañero nuevo puede levantar la app y generar un reporte siguiendo el README sin asistencia adicional.

---

**[x] T-084 · Verificación Docker end-to-end**  
*Deps:* T-082, T-083

Acciones:
- `docker-compose up --build` en entorno limpio (sin caché)
- Verificar: app arranca, migraciones se ejecutan, `/health` devuelve 200, `/` carga la UI
- Configurar con `.env` apuntando a DT v4.14.1 de prueba
- Ejecutar sincronización desde la UI
- Generar reporte trimestral .docx y .xlsx
- Verificar que el reporte coincide con el reporte de referencia Q2 2026

**DoD:** La app funciona completamente con `docker-compose up` y una configuración `.env` válida. El reporte generado es equivalente al de referencia.

---

## Resumen de dependencias

```
T-001 → T-002 → T-003
T-001 → T-004 → T-005
T-004 → T-006 → T-031 → T-032..T-036
T-004 → T-008
T-001 → T-011..T-015
T-015 → T-016
T-016 → T-017..T-019
T-016, T-031..T-036 → T-032..T-036
T-041 → T-042
T-015, T-043 → T-062
T-051 → T-052..T-054
T-016..T-019, T-034..T-036 → T-061..T-067
T-008, T-061..T-067, T-071 → T-073..T-079
T-073..T-079 → T-081..T-084
```

---

## Conteo de tareas

| Grupo | Rango | Total |
|-------|-------|-------|
| G0 — Andamiaje | T-001–T-008 | 8 |
| G1 — Dominio | T-011–T-019 | 9 |
| G2 — Persistencia | T-031–T-036 | 6 |
| G3 — Clientes externos | T-041–T-043 | 3 |
| G4 — Generadores de reportes | T-051–T-054 | 4 |
| G5 — Aplicación | T-061–T-067 | 7 |
| G6 — Interfaz web | T-071–T-079 | 9 |
| G7 — Integración | T-081–T-084 | 4 |
| **TOTAL** | | **50** |
