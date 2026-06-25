# Constitution — VulnTrack Reports

> **Versión:** 1.0  
> **Fecha:** 2026-06-23  
> **Propósito:** Principios y reglas no negociables. Toda decisión de diseño, arquitectura o implementación debe ser justificable frente a este documento. Si un principio entra en conflicto con otro, el orden aquí establece la precedencia.

---

## P-01 · Seguridad ante todo

1. **Ningún secreto en el código fuente ni en el repositorio.** API keys, URLs de instancias, contraseñas y cualquier credencial se configuran exclusivamente via variables de entorno o archivos `.env` fuera del control de versiones. Los `.env` de ejemplo (`.env.example`) solo contienen claves vacías o valores ficticios.
2. **Validación en la frontera.** Todo dato externo (entradas del usuario, respuestas de la API de Dependency-Track, feed de CISA KEV) se valida y tipifica antes de entrar al dominio. Nunca se confía en datos externos sin validar.
3. **Principio de mínimo privilegio.** El cliente de Dependency-Track solo requiere los permisos `VIEW_PORTFOLIO` y `VIEW_VULNERABILITY`. La app no solicita ni almacena permisos adicionales.
4. **La app está preparada para HTTPS y autenticación.** Aunque el MVP corra en local sin TLS, la arquitectura no debe impedir añadir ambos sin refactoring estructural.
5. **CORS controlado.** Los orígenes permitidos se configuran por entorno; nunca wildcard `*` en producción.
6. **Sin ejecución de código arbitrario.** No se evaluará (`eval`, `exec`) ningún input del usuario ni dato externo.

---

## P-02 · Corrección antes que completitud

1. **Un feature incompleto y correcto es mejor que uno completo e incorrecto.** Si hay duda entre hacer más o hacerlo bien, se hace bien.
2. **Tipado estático obligatorio.** Todo el código Python usa type hints. `mypy` en modo estricto debe pasar sin errores en el dominio y la capa de aplicación; modo menos estricto aceptable en adaptadores de infraestructura donde librerías externas dificultan el tipado.
3. **Sin supresión silenciosa de errores.** No se capturan excepciones genéricas (`except Exception`) sin re-lanzar o registrar con contexto. Los errores se propagan o se convierten en resultados explícitos (Result types / errores de dominio).

---

## P-03 · Pruebas como documentación ejecutable

1. **Primero las pruebas para lógica de dominio y casos de uso.** La lógica de priorización, cálculo de "nuevas/tratadas", generación de KPIs y el motor de reportes tienen pruebas unitarias antes o junto con la implementación.
2. **Cobertura mínima del 80 % en dominio y capa de aplicación.** La infraestructura puede tener menos cobertura, pero los adaptadores deben tener pruebas de integración.
3. **El cliente de DT es siempre mockeable.** Las pruebas de servicios de aplicación jamás llaman a una instancia real de Dependency-Track.
4. **Las pruebas son deterministas y sin efectos secundarios.** No dependen de orden de ejecución, fecha/hora real ni red externa.
5. **Nomenclatura descriptiva.** Los nombres de tests describen el escenario: `test_priorization_score_is_max_when_in_kev_and_critical`.

---

## P-04 · Arquitectura hexagonal sin compromisos

1. **El dominio no conoce el framework.** Las entidades, value objects y reglas de negocio no importan FastAPI, SQLAlchemy, httpx ni ninguna biblioteca de infraestructura.
2. **La capa de aplicación orquesta, no implementa.** Los casos de uso dependen de puertos (interfaces abstractas), nunca de adaptadores concretos.
3. **Un puerto por capacidad.** Hay un puerto para el repositorio de proyectos, otro para el cliente de DT, otro para el generador de reportes, etc. Cada puerto tiene exactamente una responsabilidad.
4. **Los DTOs viven en la capa de interfaces.** Las entidades de dominio no se serializan directamente a JSON ni se exponen al exterior; existen DTOs/schemas de Pydantic para eso.
5. **La base de datos es un detalle de infraestructura.** Cambiar de SQLite a PostgreSQL no debe requerir tocar dominio ni aplicación.

---

## P-05 · Simplicidad y YAGNI

1. **No se abstrae lo que no existe.** Solo se añaden interfaces, patrones o capas cuando hay un caso de uso real que lo justifique, no por anticipación.
2. **Un solo módulo hace una sola cosa.** Si un módulo crece más de lo que cabe en la cabeza, se divide.
3. **Sin magia implícita.** Se prefiere código explícito a decoradores mágicos o metaclases cuando la claridad importa más que la brevedad.
4. **La estructura de carpetas refleja la arquitectura.** Un lector nuevo debe inferir la separación de capas solo mirando el árbol de directorios.

---

## P-06 · Calidad de código observable

1. **Linting y formato no son opcionales.** `ruff check` y `ruff format` pasan sin errores. Las reglas se configuran en `pyproject.toml` y no se silencian inline salvo casos documentados.
2. **Pre-commit hooks obligatorios.** Cada commit ejecuta al menos: ruff, mypy, y los tests de dominio rápidos.
3. **Los commits son atómicos y descriptivos.** Cada commit representa un cambio coherente con un mensaje que describe el QUÉ y el POR QUÉ. Formato: `tipo(alcance): descripción` (e.g., `feat(sync): agregar paginación idempotente para proyectos DT`).
4. **Sin código muerto en el repositorio.** Código comentado, imports sin usar y variables sin usar no pasan la revisión.

---

## P-07 · Observabilidad integrada

1. **Logging estructurado desde el principio.** Se usa `structlog` o el módulo estándar con formato JSON configurable. Nunca `print()` en código de producción.
2. **Cada operación significativa tiene un log.** Sincronización iniciada/completada, errores de conexión, reportes generados, tareas de remediación actualizadas.
3. **Los errores tienen contexto.** Un log de error incluye: qué operación falló, con qué parámetros (sin datos sensibles), y qué excepción se produjo.
4. **Healthcheck expuesto.** La app expone `/health` que verifica conexión a la base de datos y, opcionalmente, a la instancia de DT.

---

## P-08 · Reproducibilidad y despliegue

1. **Docker es la única forma de ejecutar la app en producción.** El `Dockerfile` es el artefacto de despliegue; `docker-compose` gestiona dependencias locales.
2. **12-Factor App.** Configuración por entorno, sin estado en el sistema de archivos del contenedor (salvo volúmenes montados), logs a stdout/stderr.
3. **Las migraciones son código versionado.** Alembic gestiona todos los cambios de esquema; nunca se altera la base de datos manualmente.
4. **El entorno de desarrollo es reproducible.** `uv sync` (o `poetry install`) + `pre-commit install` es todo lo que hace falta después de clonar el repo.

---

## P-09 · Internacionalización y legibilidad

1. **La UI, los reportes y la documentación están en español.** Los términos técnicos de la industria (CVE, EPSS, KEV, severity, finding) pueden mantenerse en inglés.
2. **El código (variables, funciones, clases, comentarios de código) está en inglés.** Esto facilita el uso de herramientas estándar de la industria y la colaboración con equipos internacionales.
3. **Los comentarios explican el POR QUÉ, no el QUÉ.** El QUÉ lo explica el nombre del símbolo.

---

## P-10 · Extensibilidad controlada

1. **Los puntos de extensión se declaran en el spec antes de implementarse.** No se añaden "por si acaso".
2. **El motor de priorización usa el patrón Estrategia.** Cambiar los pesos o la fórmula no requiere tocar el código de los casos de uso.
3. **El generador de reportes acepta nuevos formatos sin modificar la lógica de datos.** El adaptador de cada formato (Word, Excel, PDF) implementa un puerto común.
4. **Las fuentes de datos externas (DT, KEV, futuras) son adaptadores intercambiables.** Añadir una nueva fuente es implementar un puerto existente, no extender la aplicación.

---

## Supuestos documentados (pendientes de confirmación)

| ID | Supuesto | Impacto si es incorrecto |
|----|----------|--------------------------|
| A-01 | Una sola instancia de DT por entorno | Si hay múltiples instancias, el plan debe incluir un modelo de "tenancy" |
| A-02 | MVP monousuario o con autenticación básica (usuario+contraseña) | Si se requiere SSO/LDAP desde el inicio, la arquitectura de auth cambia |
| A-03 | DT versión 4.x (API v1 estable) | Si es versión 3.x, algunos endpoints pueden diferir |
| A-04 | El export a PDF puede ser post-MVP | Si es bloqueante, entra en el scope del MVP |
| A-05 | Los planes de trabajo son internos a la app (sin integración con Jira/ADO) | Si se requiere integración, hay que añadir un puerto de ticketero |
| A-06 | CI en GitHub Actions | Fácil de cambiar; solo afecta el archivo de configuración |
| A-07 | SQLite en local/dev, PostgreSQL en producción | Si SQLite es aceptable en prod, se simplifica el despliegue |
