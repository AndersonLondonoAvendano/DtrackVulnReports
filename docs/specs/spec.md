# Spec — VulnTrack Reports

> **Versión:** 1.1  
> **Fecha:** 2026-06-23  
> **Cambios v1.1:** Supuestos confirmados incorporados; estructura del reporte de referencia documentada; fórmula de priorización definida; ajustes de alcance (PDF en scope; exportación de planes; KEV on-demand).

---

## 1. Problema

### 1.1 Situación actual

El equipo de seguridad gestiona los hallazgos de vulnerabilidades de múltiples proyectos de software a través de **Dependency-Track (DT)**, una plataforma OWASP de análisis de composición de software (SCA). DT expone toda su información mediante una API REST.

Sin embargo, el proceso actual de reporte tiene los siguientes problemas:

| Problema | Consecuencia |
|----------|--------------|
| **Proceso 100 % manual**: un analista entra proyecto por proyecto en el dashboard de DT para leer métricas y severidades | Consume horas de trabajo repetitivo; es propenso a errores y omisiones |
| **Sin visión consolidada automática**: no existe una vista de portafolio actualizada | La dirección no tiene visibilidad del estado global de vulnerabilidades sin que alguien lo construya manualmente |
| **Sin trazabilidad de avance**: los reportes son snapshots puntuales, no comparan inicio vs fin de un período | No se puede demostrar el trabajo de remediación ni medir la velocidad de tratamiento |
| **Sin priorización sistemática**: se trabaja por severidad simple sin considerar EPSS ni presencia en KEV | Recursos de remediación mal asignados; CVEs explotados activamente pueden no recibir atención prioritaria |
| **Sin seguimiento de remediación**: no hay un sistema que vincule hallazgos de DT con tareas de trabajo asignadas y fechas objetivo | Los planes de remediación viven en hojas de cálculo desconectadas |

### 1.2 Oportunidad

DT (v4.13.3 en producción / v4.14.1 en pruebas) tiene una API completa con datos de proyectos, métricas históricas, hallazgos detallados (CVE, CVSS, EPSS) y componentes. El catálogo KEV de CISA es público y actualizable. Con esos datos se puede construir una plataforma que automatice completamente el ciclo de reporte y remediación.

---

## 2. Objetivos

### 2.1 Objetivo principal

Automatizar la generación de reportes de vulnerabilidades y el seguimiento de remediación, eliminando el trabajo manual repetitivo y proveyendo una visión consolidada y priorizada del estado de seguridad del portafolio.

### 2.2 Objetivos medibles (MVP)

| ID | Objetivo | Métrica de éxito |
|----|----------|-----------------|
| O-01 | Eliminar la recopilación manual de datos de DT | Tiempo de generación de reporte < 2 minutos (vs horas actualmente) |
| O-02 | Proveer visión consolidada del portafolio | Dashboard con estado de todos los proyectos disponible en todo momento |
| O-03 | Automatizar reportes de avance por período | Reporte de "nuevas y tratadas por severidad" generado en un clic para cualquier rango de fechas |
| O-04 | Priorizar vulnerabilidades con criterios objetivos | Lista priorizada combinando severidad + CVSS + EPSS + KEV disponible por proyecto y portafolio |
| O-05 | Dar seguimiento a remediación | Planes de trabajo asociados a hallazgos con estado, responsable y fecha objetivo, exportables |

---

## 3. Alcance

### 3.1 En scope (MVP)

- **Sincronización**: conectar a una instancia de DT y sincronizar/cachear proyectos, métricas actuales e históricas, y hallazgos.
- **Dashboard web**: vista consolidada del portafolio con indicadores principales de vulnerabilidades.
- **Catálogo de proyectos**: listado de proyectos con su estado de vulnerabilidades actual.
- **Reportes exportables (.docx, .xlsx, .pdf)**: generación de reportes con gráficas y tablas con mapa de calor por severidad, equivalentes o superiores al reporte de referencia Q2 2026, para períodos semanales, mensuales, trimestrales o rango de fechas libre.
- **Reportes de avance**: cálculo de vulnerabilidades nuevas y tratadas por severidad para un rango de fechas dado.
- **Priorización de vulnerabilidades**: listado priorizado combinando severidad + CVSS + EPSS + presencia en KEV (con fórmula y pesos configurables), por proyecto y a nivel portafolio.
- **Cruce con CISA KEV**: identificar qué proyectos y componentes están afectados por CVEs del catálogo KEV; actualización del catálogo on-demand desde la UI.
- **Reporte de umbrales CVSS/EPSS**: export de hallazgos que superan umbrales configurables de CVSSv3 y EPSS.
- **Planes de trabajo / remediación**: creación, asignación, priorización y seguimiento de tareas de remediación basadas en hallazgos, con estado, responsable, fecha objetivo y notas; exportables en .xlsx o .pdf; con recomendaciones inteligentes basadas en severidad, KEV, EPSS y CVSS.
- **Configuración de conexión a DT**: gestión de la conexión (URL + API Key) por entorno, sin hardcoding.
- **Despliegue con Docker**: la app corre con `docker-compose up` sin pasos manuales adicionales.

### 3.2 Fuera de scope (MVP)

- Múltiples instancias de DT simultáneas (una sola instancia).
- Autenticación de usuarios con roles (admin, analista, lector) — MVP monousuario; bases para multiusuario documentadas.
- Integración con sistemas de ticketing externos (Jira, GLPI, etc.) — bases para integración futura dejadas en el código.
- Importación de SBOMs o escaneos (DT sigue siendo la fuente de verdad).
- Gestión de políticas de DT desde esta app.
- Soporte para múltiples organizaciones o tenants.
- CI/CD automatizado (GitLab CI es el objetivo a futuro, fuera de scope del MVP).

### 3.3 Bases para el futuro (diseñadas para no bloquear)

- Escalado a PostgreSQL u otra base de datos relacional.
- Autenticación de usuarios con roles.
- Integración con Jira/GLPI (puerto de ticketera definido, sin implementar).
- Notificaciones push/email por nuevas vulnerabilidades críticas.
- CI/CD con GitLab CI.

---

## 4. Personas / Usuarios

### P-1 · Analista de Seguridad

**Perfil:** Persona técnica responsable de gestionar vulnerabilidades día a día. Usa DT directamente hoy, pero invierte horas en construir reportes manuales.

**Necesidades:**
- Ver el estado actual de vulnerabilidades de todos los proyectos sin entrar uno por uno.
- Saber qué vulnerabilidades priorizar (no solo por severidad, también por EPSS y KEV).
- Construir reportes de avance en minutos, no horas; exportarlos en Word, Excel y PDF.
- Registrar y hacer seguimiento de las tareas de remediación asignadas a su equipo.
- Compartir el plan de remediación con el equipo de desarrollo.

**Frustraciones actuales:** Pérdida de tiempo en recopilación manual; imposibilidad de comparar avance entre períodos sin trabajo extra; sin visibilidad de qué vulnerabilidades son explotadas activamente.

---

### P-2 · Director / Gerente de Seguridad

**Perfil:** Stakeholder ejecutivo que necesita una visión de alto nivel para tomar decisiones y reportar hacia la organización.

**Necesidades:**
- Dashboard con el estado consolidado del portafolio, siempre actualizado.
- Reportes ejecutivos exportables (Word/Excel/PDF) equivalentes al reporte Q2 2026, generados en un clic.
- Métricas de avance: ¿estamos mejorando? ¿cuántas vulnerabilidades tratamos este mes/trimestre?

**Frustraciones actuales:** Depende del analista para obtener un reporte; los reportes son puntuales y no muestran tendencia.

---

### P-3 · Desarrollador / Equipo de desarrollo

**Perfil:** Responsable de implementar las correcciones. No usa DT directamente; recibe las tareas de remediación del analista.

**Necesidades:**
- Ver las vulnerabilidades que le fueron asignadas, con contexto (componente, versión, CVE, severidad, prioridad).
- Actualizar el estado de sus tareas de remediación.
- Saber cuáles son las más urgentes (KEV primero, luego por score de prioridad).

---

## 5. Épicas e Historias de Usuario

### ÉPICA 1 — Sincronización y disponibilidad de datos

---

**HU-101 — Configurar conexión a Dependency-Track**

Como analista de seguridad,  
quiero configurar la URL y la API Key de la instancia de DT,  
para que la plataforma pueda conectarse a los datos de mi organización.

*Criterios de aceptación:*

- **Given** que tengo una instancia de DT (v4.13.x o v4.14.x) con una API Key con permisos `VIEW_PORTFOLIO` y `VIEW_VULNERABILITY`,  
  **When** ingreso la URL base y la API Key en la configuración de la app,  
  **Then** la app valida la conexión y muestra "Conexión exitosa" con la versión de DT detectada.

- **Given** que la URL o la API Key son incorrectas,  
  **When** intento guardar la configuración,  
  **Then** la app muestra un mensaje de error descriptivo (p.ej. "No se pudo conectar: timeout" o "API Key inválida: 401") sin revelar el valor de la API Key en el log.

- **Given** que la configuración existe en el `.env`,  
  **When** la app inicia,  
  **Then** usa esa configuración automáticamente sin requerir intervención del usuario.

---

**HU-102 — Sincronizar proyectos y métricas actuales**

Como analista de seguridad,  
quiero sincronizar la lista de proyectos y sus métricas actuales desde DT,  
para tener una vista local actualizada.

*Criterios de aceptación:*

- **Given** que la conexión a DT está configurada,  
  **When** ejecuto una sincronización manual,  
  **Then** la app obtiene todos los proyectos (respetando paginación con `X-Total-Count`) y sus métricas actuales (Critical, High, Medium, Low, Unassigned, riskScore) y los almacena localmente.

- **Given** que hay proyectos ya existentes en la cache local,  
  **When** se sincroniza,  
  **Then** los registros se actualizan (upsert idempotente) sin duplicados.

- **Given** que DT devuelve un error temporal durante la sincronización,  
  **When** ocurre el error,  
  **Then** la app reintenta con backoff exponencial hasta N veces, registra el error con contexto, y no pierde los datos ya obtenidos.

---

**HU-103 — Sincronizar hallazgos detallados**

Como analista de seguridad,  
quiero que la plataforma sincronice los hallazgos (findings) de cada proyecto,  
para poder filtrar, priorizar y exportar vulnerabilidades con detalle de componente, CVE, CVSS y EPSS.

*Criterios de aceptación:*

- **Given** que un proyecto fue sincronizado,  
  **When** se obtienen sus findings,  
  **Then** cada finding incluye: componente, versión, CVE, severidad, cvssV3BaseScore, epssScore y `attributedOn`.

- **Given** que un finding ya existe en la cache local,  
  **When** se re-sincroniza,  
  **Then** se actualiza si cambió el estado pero se conserva la `attributedOn` original.

---

**HU-104 — Sincronización programada automática**

Como analista de seguridad,  
quiero que la sincronización ocurra automáticamente a intervalos configurables,  
para que la información esté siempre actualizada.

*Criterios de aceptación:*

- **Given** que el intervalo de sincronización está configurado (por defecto: cada 6 horas),  
  **When** se alcanza el intervalo,  
  **Then** la app inicia una sincronización completa en background sin interrumpir la interfaz.

---

**HU-105 — Guardar snapshots de métricas históricas**

Como analista de seguridad,  
quiero que la plataforma guarde snapshots diarios de las métricas de cada proyecto,  
para calcular avance entre fechas con total precisión, independientemente de la retención de DT.

*Criterios de aceptación:*

- **Given** que se ejecuta la sincronización diaria,  
  **When** se obtienen las métricas de un proyecto,  
  **Then** se guarda un snapshot local con fecha, proyecto y conteos por severidad (Critical/High/Medium/Low/Unassigned/Total/riskScore).

- **Given** que ya existe un snapshot para ese día y proyecto,  
  **When** se re-sincroniza el mismo día,  
  **Then** el snapshot se actualiza (no se duplica).

---

### ÉPICA 2 — Dashboard y catálogo de proyectos

---

**HU-201 — Ver dashboard consolidado del portafolio**

Como director de seguridad,  
quiero un dashboard con los indicadores consolidados del portafolio,  
para tener visibilidad inmediata del estado global de vulnerabilidades.

*Criterios de aceptación:*

- **Given** que hay datos sincronizados,  
  **When** entro al dashboard,  
  **Then** veo: total vigentes, total nuevas en el período, total tratadas (reducción), proyectos en cero, y un desglose por severidad (Críticas/Altas/Medias/Bajas/Sin asignar).

- **Given** que los datos tienen más de N horas de antigüedad (configurable),  
  **When** entro al dashboard,  
  **Then** se muestra un aviso "datos desactualizados" con la fecha del último sync.

---

**HU-202 — Ver catálogo de proyectos con estado de vulnerabilidades**

Como analista de seguridad,  
quiero ver la lista de todos los proyectos con su conteo de vulnerabilidades por severidad,  
para identificar rápidamente los proyectos más críticos.

*Criterios de aceptación:*

- **Given** que hay proyectos sincronizados,  
  **When** accedo al catálogo,  
  **Then** veo una tabla con: nombre, versión, Crít./Alta/Media/Baja/Sin asig./Total/Riesgo, y fecha de última sincronización, ordenable por cualquier columna.

- **Given** que hago clic en un proyecto,  
  **When** accedo al detalle,  
  **Then** veo métricas actuales, lista de hallazgos priorizados y planes de trabajo asociados.

---

### ÉPICA 3 — Reportes exportables

---

**HU-301 — Generar reporte consolidado del portafolio**

Como director de seguridad,  
quiero generar un reporte consolidado de todas las vulnerabilidades del portafolio para un período dado,  
para presentarlo a la dirección sin trabajo manual.

*Criterios de aceptación:*

- **Given** que hay datos sincronizados para el período seleccionado,  
  **When** selecciono el período y solicito el reporte consolidado,  
  **Then** la app genera .docx / .xlsx / .pdf que incluyen todas las secciones del reporte de referencia (ver §7).

- **Given** que el reporte fue generado,  
  **When** el usuario hace clic en "Descargar",  
  **Then** recibe el archivo con nombre descriptivo (p.ej. `Reporte_Portafolio_2026-Q2.docx`).

---

**HU-302 — Generar reporte por proyecto**

Como analista de seguridad,  
quiero generar un reporte de vulnerabilidades para un proyecto específico y un rango de fechas,  
para presentarlo al equipo de desarrollo correspondiente.

*Criterios de aceptación:*

- **Given** que selecciono un proyecto y un período,  
  **When** solicito el reporte por proyecto,  
  **Then** el .docx / .xlsx / .pdf incluyen: estado actual por severidad, gráfica de distribución (donut), hallazgos ordenados por score de prioridad (con columnas CVE, componente, versión, severidad, CVSS, EPSS, en KEV), evolución inicio vs actual, y plan de trabajo abierto.

- **Given** que el proyecto tiene hallazgos en KEV,  
  **When** se genera el reporte,  
  **Then** esos hallazgos están marcados visualmente con etiqueta "KEV" y color destacado.

---

**HU-303 — Configurar parámetros del reporte**

Como analista de seguridad,  
quiero configurar los parámetros del reporte antes de generarlo,  
para adaptar el output a la audiencia y el período de interés.

*Criterios de aceptación:*

- **Given** que voy a generar un reporte,  
  **When** abro el formulario,  
  **Then** puedo seleccionar:
  - Período: **Semanal** (últimos 7 días), **Mensual** (mes calendario), **Trimestral** (Q1/Q2/Q3/Q4), o **Rango libre** (fecha inicio / fecha fin).
  - Proyectos: todos o una selección múltiple.
  - Tipo: Consolidado o Por proyecto.
  - Formato de salida: Word (.docx), Excel (.xlsx), PDF (.pdf), o todos.

- **Given** que selecciono rango libre y el inicio es posterior al fin,  
  **When** intento generar,  
  **Then** la app muestra un error de validación antes de procesar.

---

### ÉPICA 4 — Reportes de avance (nuevas y tratadas)

---

**HU-401 — Calcular vulnerabilidades nuevas en un período**

Como analista de seguridad,  
quiero saber cuántas vulnerabilidades nuevas aparecieron en un período dado, por severidad y por proyecto,  
para entender el ritmo de entrada de riesgo nuevo.

*Criterios de aceptación:*

- **Given** que selecciono un período,  
  **When** consulto las vulnerabilidades nuevas,  
  **Then** la plataforma lista los hallazgos cuya `attributedOn` cae dentro del rango, agrupados por severidad y por proyecto, con totales (equivalente a la sección "Vulnerabilidades nuevas" del reporte de referencia).

---

**HU-402 — Calcular vulnerabilidades tratadas por severidad en un período**

Como director de seguridad,  
quiero saber cuántas vulnerabilidades se trataron por nivel de severidad en un período dado,  
para demostrar el avance del equipo de remediación.

*Criterios de aceptación:*

- **Given** que selecciono un período con snapshots disponibles en ambos extremos,  
  **When** consulto las tratadas,  
  **Then** la plataforma calcula: Variación = (conteo al inicio) − (conteo al fin) por proyecto, y Tratadas = max(0, Variación) por proyecto, tanto por severidad total como consolidado — equivalente a la tabla "Evolución y tratamiento" del reporte de referencia.

- **Given** que un proyecto aumentó vulnerabilidades en el período,  
  **When** se calcula el avance,  
  **Then** la variación aparece en positivo (rojo) y "Tratadas" = 0, sin ocultar que ese proyecto empeoró.

- **Given** que no hay snapshot al inicio del período,  
  **When** se calcula el avance,  
  **Then** la app avisa que los datos históricos para esa fecha no están disponibles e indica el rango disponible.

---

### ÉPICA 5 — Priorización de vulnerabilidades

---

**HU-501 — Ver lista priorizada de vulnerabilidades del portafolio**

Como analista de seguridad,  
quiero ver una lista de todas las vulnerabilidades del portafolio ordenada por un score de prioridad combinado,  
para enfocar el esfuerzo de remediación en los riesgos más reales primero.

*Criterios de aceptación:*

- **Given** que hay hallazgos sincronizados,  
  **When** accedo a la vista de priorización,  
  **Then** veo una tabla con: CVE, componente, versión, proyecto(s), severidad, CVSS, EPSS, en KEV (sí/no), y score de prioridad (0–100).

- **Given** que filtro por "solo KEV",  
  **When** aplico el filtro,  
  **Then** solo se muestran los hallazgos cuyos CVEs están en el catálogo KEV de CISA.

---

**HU-502 — Fórmula y pesos del score de priorización**

Como analista de seguridad,  
quiero que el score de prioridad refleje las mejores prácticas de la industria en gestión de vulnerabilidades,  
y poder ajustar sus pesos según la política de riesgo de mi organización.

*Definición de la fórmula base (ver §8 para justificación):*

```
priority_score = clamp(
    cvss_normalized * W_cvss  +
    epss_score      * W_epss  +
    kev_flag        * W_kev,
    min=0.0, max=1.0
)

donde:
  cvss_normalized = cvss_v3_base_score / 10.0   (0.0 – 1.0)
  kev_flag        = 1.0 si el CVE está en KEV, 0.0 si no

Pesos por defecto:
  W_cvss = 0.30
  W_epss = 0.40
  W_kev  = 0.30

Regla de elevación obligatoria:
  si kev_flag = 1.0 → priority_score = max(priority_score, 0.75)
```

Score se muestra escalado 0–100 en la UI. Resultado se clasifica en bandas:
- 75–100: Inmediata (rojo)
- 50–74: Alta (naranja)
- 25–49: Media (amarillo)
- 0–24: Baja (verde)

*Criterios de aceptación:*

- **Given** que un hallazgo tiene CVE en KEV con CVSS=9.8 y EPSS=0.85,  
  **When** se calcula el score,  
  **Then** score = clamp(0.98×0.30 + 0.85×0.40 + 1.0×0.30, …) = clamp(0.928, …) = 92.8 → banda Inmediata.

- **Given** que el analista cambia W_epss a 0.50 y W_cvss a 0.20,  
  **When** guarda la configuración,  
  **Then** la lista se recalcula con los nuevos pesos inmediatamente.

- **Given** que no se han configurado pesos personalizados,  
  **When** se calcula el score,  
  **Then** se usan los pesos por defecto documentados arriba.

---

### ÉPICA 6 — Cruce con CISA KEV y utilidades de comunidad

---

**HU-601 — Cruzar hallazgos con el catálogo KEV de CISA**

Como analista de seguridad,  
quiero saber qué proyectos y componentes de mi portafolio tienen CVEs presentes en el catálogo KEV de CISA,  
para tomar acción inmediata en las vulnerabilidades más peligrosas.

*Criterios de aceptación:*

- **Given** que el catálogo KEV está descargado y los hallazgos están sincronizados,  
  **When** accedo a la vista KEV,  
  **Then** veo la lista de hallazgos afectados con: CVE ID, componente, versión, proyecto, descripción KEV, fecha de adición al catálogo, y acción requerida por CISA.

- **Given** que es la primera vez o el catálogo no existe,  
  **When** accedo a la vista KEV,  
  **Then** la app descarga automáticamente el JSON de CISA antes de mostrar resultados.

---

**HU-602 — Actualizar el catálogo KEV on-demand**

Como analista de seguridad,  
quiero poder actualizar el catálogo KEV desde la UI con un solo clic,  
para tener siempre la lista más reciente de CVEs explotados activamente, cuando lo necesite.

*Criterios de aceptación:*

- **Given** que estoy en la vista de KEV o en la configuración,  
  **When** hago clic en "Actualizar catálogo KEV",  
  **Then** la app descarga el JSON de CISA, actualiza el catálogo local, muestra la fecha de la actualización y recalcula el cruce con los hallazgos actuales.

- **Given** que el catálogo tiene más de 7 días sin actualizar,  
  **When** accedo a cualquier vista que use KEV,  
  **Then** se muestra un aviso no bloqueante con la fecha del último update y un botón "Actualizar ahora".

- **Given** que la descarga falla (error de red),  
  **When** ocurre el fallo,  
  **Then** la app conserva el catálogo anterior, muestra un error claro, y no deja el catálogo en estado inválido.

---

**HU-603 — Reporte de componentes sobre umbrales CVSS/EPSS**

Como analista de seguridad,  
quiero un listado/reporte de componentes que superen umbrales configurables de CVSSv3 y EPSS,  
para identificar rápidamente qué actualizar en base a puntuación de explotabilidad real.

*Criterios de aceptación:*

- **Given** que configuro umbrales (p.ej. CVSS ≥ 7.0 Y EPSS ≥ 0.10),  
  **When** ejecuto el reporte,  
  **Then** obtengo una lista con: CVE, componente, versión, proyecto, CVSS, EPSS, en KEV, exportable a .xlsx.

- **Given** que no hay hallazgos que superen los umbrales,  
  **When** ejecuto el reporte,  
  **Then** se muestra "No se encontraron componentes que superen los umbrales configurados" (no un error).

---

### ÉPICA 7 — Planes de trabajo / Remediación inteligente

---

**HU-701 — Crear plan de trabajo para un proyecto**

Como analista de seguridad,  
quiero crear un plan de trabajo para un proyecto con tareas de remediación derivadas de sus hallazgos,  
y que la plataforma sugiera prioridades y recomendaciones basadas en las mejores prácticas de ciberseguridad.

*Criterios de aceptación:*

- **Given** que estoy en el detalle de un proyecto,  
  **When** creo una tarea de remediación,  
  **Then** puedo asociarla a un hallazgo (CVE), asignar un responsable (texto libre), establecer una fecha objetivo, definir el estado (Pendiente / En progreso / Completado / Descartado) y agregar notas.

- **Given** que el proyecto tiene hallazgos en KEV,  
  **When** visualizo el plan de trabajo sugerido,  
  **Then** los hallazgos KEV aparecen al tope con recomendación "Remediación inmediata — explotación activa confirmada".

- **Given** que un hallazgo tiene EPSS ≥ 0.5 aunque no esté en KEV,  
  **When** se sugiere la prioridad de la tarea,  
  **Then** se recomienda "Alta prioridad — alta probabilidad de explotación en los próximos 30 días".

---

**HU-702 — Exportar plan de trabajo**

Como analista de seguridad,  
quiero exportar el plan de trabajo de un proyecto,  
para compartirlo con el equipo de desarrollo y darles acceso a la información sin que necesiten la plataforma.

*Criterios de aceptación:*

- **Given** que existe un plan de trabajo para un proyecto,  
  **When** hago clic en "Exportar plan",  
  **Then** descargo un .xlsx o .pdf con: proyecto, hallazgo (CVE, componente, versión, severidad, CVSS, EPSS, en KEV), tarea, responsable, fecha objetivo, estado, notas, y score de prioridad.

- **Given** que el plan tiene tareas en múltiples estados,  
  **When** se exporta,  
  **Then** el archivo incluye un resumen con conteo de tareas por estado y porcentaje de avance.

---

**HU-703 — Actualizar el estado de una tarea de remediación**

Como analista de seguridad o desarrollador,  
quiero actualizar el estado de una tarea de remediación,  
para que el equipo tenga visibilidad del progreso.

*Criterios de aceptación:*

- **Given** que existe una tarea,  
  **When** cambio el estado a "Completado",  
  **Then** la tarea se marca con la fecha de actualización y aparece en el resumen de avance.

- **Given** que una tarea tiene fecha objetivo vencida y no está completada,  
  **When** aparece en el listado,  
  **Then** se destaca visualmente (etiqueta "Vencida" en rojo).

---

**HU-704 — Ver resumen de planes de trabajo en el dashboard**

Como director de seguridad,  
quiero ver en el dashboard cuántas tareas de remediación están abiertas, en progreso y completadas,  
para entender la velocidad de ejecución del equipo.

*Criterios de aceptación:*

- **Given** que hay planes de trabajo creados,  
  **When** entro al dashboard,  
  **Then** veo: tareas abiertas, en progreso, completadas este período, y vencidas.

---

## 6. Restricciones conocidas

| ID | Restricción |
|----|------------|
| R-01 | La autenticación hacia DT se hace exclusivamente con `X-Api-Key`. |
| R-02 | La precisión del cálculo de "tratadas" depende de snapshots disponibles para los extremos del período. Si no hay snapshot en la fecha de inicio solicitada, el cálculo no es exacto. |
| R-03 | El campo `attributedOn` de DT es la fuente de verdad para "cuándo apareció un hallazgo". Si es nulo (hallazgos heredados), la fecha puede no estar disponible. |
| R-04 | El catálogo KEV de CISA es externo; si no hay conectividad a internet, se usa el último descargado (con aviso). La actualización es on-demand desde la UI. |
| R-05 | DT versión de producción (v4.13.3) y de pruebas (v4.14.1) pueden tener diferencias menores en la API; la implementación debe ser tolerante a diferencias de versión menor. |
| R-06 | El EPSS score puede ser nulo para CVEs muy recientes. La fórmula de priorización debe manejar `epss_score = None` como 0.0 con un aviso. |

---

## 7. Estructura de referencia del reporte (canónica)

*Derivada del reporte "Reporte de Vulnerabilidades – Desarrollo Q2 2026" provisto por el usuario.*

### 7.1 Secciones obligatorias (en orden)

| # | Sección | Contenido |
|---|---------|-----------|
| 1 | **Portada / Encabezado** | Título, período, fuente (DT + OSS Index/NVD), autor |
| 2 | **Banner de KPIs** (4 cards) | Vigentes (gris), Nuevas en el período (rojo/naranja), Tratadas/reducción (verde), Proyectos en cero (azul) |
| 3 | **Párrafo ejecutivo** | Texto narrativo con resumen de los KPIs y hallazgos más relevantes |
| 4 | **Estado actual** | Donut chart "Inventario vigente por gravedad" (total en el centro), tabla heatmap proyectos × severidades + Total + Riesgo, barra horizontal de vulnerabilidades vigentes por proyecto |
| 5 | **Vulnerabilidades nuevas en el período** | Donut chart "Nuevas por gravedad", tabla heatmap proyectos × severidades nuevas + Total, barra horizontal de ingresos por proyecto, párrafo narrativo con patrones detectados |
| 6 | **Evolución y tratamiento** | Gráfica de barras divergentes (verde = reducción, rojo = incremento), tabla: Proyecto / Inicio / Actual / Variación / Tratadas, párrafo narrativo con análisis |
| 7 | **Conclusiones y recomendaciones** | Bullet points con acciones concretas |
| 8 | **Pie de firma** | Tabla: Elaboró / Revisó / Aprobó |

### 7.2 Paleta de colores (heatmap y gráficas)

| Severidad | Color hex (referencia) | Uso |
|-----------|----------------------|-----|
| Crítica | `#C00000` rojo oscuro | Celda, leyenda, etiqueta |
| Alta | `#FF6600` naranja | Celda, leyenda, etiqueta |
| Media | `#FFC000` ámbar/amarillo | Celda, leyenda, etiqueta |
| Baja | `#00B050` verde | Celda, leyenda, etiqueta |
| Sin asignar | `#808080` gris | Celda, leyenda, etiqueta |
| Tratadas (reducción) | `#00B050` verde | Barra divergente, celda Tratadas |
| Incremento | `#C00000` rojo | Barra divergente, variación positiva |

### 7.3 Notas de diseño

- Las tablas tienen encabezado en fondo azul marino oscuro con texto blanco.
- La columna "Riesgo" tiene fondo rojo escalado (más oscuro = mayor riesgo).
- Las gráficas de donut muestran el total y porcentajes en la leyenda: "Críticas: 26 (12%)".
- Las barras horizontales muestran el valor al final de cada barra.
- La gráfica "Inicio vs Actual" usa dos barras paralelas por proyecto (azul = inicio, rojo = actual).
- La gráfica de evolución divergente tiene cero en el centro; verde a la izquierda (reducción), rojo a la derecha (incremento).

---

## 8. Justificación de la fórmula de priorización

La fórmula propuesta combina tres dimensiones reconocidas por la industria:

| Dimensión | Peso | Justificación |
|-----------|------|---------------|
| **CVSS v3 Base Score** | 0.30 | Mide el impacto técnico potencial (confidencialidad, integridad, disponibilidad). Fuente: NIST NVD. Limitación: no indica probabilidad de explotación real. |
| **EPSS Score** | 0.40 | *Exploit Prediction Scoring System* — mide la probabilidad de que un CVE sea explotado en los próximos 30 días. Fuente: FIRST.org. Estudios muestran que EPSS predice mejor que CVSS qué vulnerabilidades serán explotadas en la práctica. Recibe el mayor peso. |
| **Presencia en KEV** | 0.30 | El catálogo CISA KEV confirma explotación activa en el mundo real. Si un CVE está en KEV, el riesgo es inmediato e incontestable. La regla de elevación (mínimo 0.75) garantiza que ningún CVE-KEV quede en banda baja. |

**Referencias:** CISA SSVC (Stakeholder-Specific Vulnerability Categorization), FIRST EPSS v3, NIST SP 800-40 Rev. 4.

---

## 9. Supuestos confirmados

| ID | Supuesto | Estado |
|----|----------|--------|
| A-01 | Una sola instancia de DT por entorno | **CONFIRMADO** |
| A-02 | MVP monousuario; bases de código para multiusuario futuro | **CONFIRMADO** |
| A-03 | DT v4.13.3 en producción / v4.14.1 en pruebas; API v1 compatible | **CONFIRMADO** |
| A-04 | Export a PDF **en scope** del MVP | **CONFIRMADO** |
| A-05 | Planes de trabajo internos + exportables; puerto de ticketera (Jira/GLPI) definido pero no implementado | **CONFIRMADO** |
| A-06 | CI en GitLab CI — fuera de scope del MVP | **CONFIRMADO** |
| A-07 | SQLite en local/dev; arquitectura permite escalar a PostgreSQL sin cambios en dominio/aplicación | **CONFIRMADO** |
| A-08 | Fórmula de priorización definida en §5/HU-502 y §8, basada en mejores prácticas (CVSS+EPSS+KEV) | **CONFIRMADO** |
| A-09 | ~22 proyectos en producción / ~707 vulnerabilidades; diseño para < 200 proyectos / < 10.000 hallazgos sin cambios de arquitectura | **CONFIRMADO** |
| A-10 | Actualización del catálogo KEV: on-demand desde la UI (botón "Actualizar KEV"); aviso si > 7 días sin actualizar | **CONFIRMADO** |
| A-11 | Períodos de reporte: Semanal / Mensual / Trimestral / Rango libre | **CONFIRMADO** |
