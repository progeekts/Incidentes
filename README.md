# Incidentes

Portal público para registrar y consultar incidentes de ciberseguridad relevantes para usuarios cotidianos.

## Objetivo

Priorizar desarrollos materialmente importantes y explicarlos de forma práctica: qué cambió, por qué importa, quién puede estar afectado y qué hacer a continuación.

## Estructura

- `index.html`: interfaz principal.
- `styles.css`: diseño responsive.
- `app.js`: filtros, búsqueda y renderizado.
- `incidents.js`: histórico de incidentes.

## Cómo añadir un incidente

Añade una nueva entrada al array `window.INCIDENTS` en `incidents.js`. Cada registro incluye fecha, organización, tipo, severidad, estado, alcance, resumen, impacto, afectados, acciones recomendadas, fuentes y notas.

## Criterios

Se priorizan fraudes o phishing masivos, brechas de datos, vulnerabilidades críticas, malware y otros incidentes con impacto real potencial para usuarios. Las afirmaciones no confirmadas deben quedar señaladas como tales y las fichas deben enlazar fuentes verificables.

## Publicación

El proyecto está preparado para funcionar como sitio estático mediante GitHub Pages desde la rama `main`.

## Actualizaciones programadas y seguimiento

El workflow `.github/workflows/update-feeds.yml` se ejecuta a las **08:00 y 20:00 (Europe/Madrid)**; admite inicio manual mediante `workflow_dispatch`.

1. `scripts/update_source_feeds.py` recopila avisos externos en `source-alerts.json`. El conjunto de avisos no equivale a incidentes editorialmente verificados.
2. `scripts/review_existing_incidents.py` consulta las fuentes enlazadas en un máximo de **10 incidentes por ejecución** y **2 enlaces por incidente**, con timeout de **9 segundos por enlace** y presupuesto temporal de **225 segundos**. Los resultados se guardan en `incident-review-state.json`.
3. Se revisan los incidentes activos o críticos aproximadamente cada día; los que están en investigación cada 3 días, los de seguimiento cada 7 días y los resueltos cada 30 días. Una fuente inaccesible se reintenta tras 24 horas. La cola prioriza incidentes de mayor riesgo y los pendientes más antiguos.
4. Al detectar cambios en una página enlazada, se conserva su URL como `pendingEvidence` y queda con `editorialReview: pending`. **No se modifica automáticamente el contenido de `incidents.json`, `incidents.js`, su cronología, sus estados ni sus recomendaciones.** La comparación de páginas web es orientativa; puede haber falsos positivos por modificaciones de diseño o textos ajenos al incidente.
5. El primer acceso a una fuente establece una referencia de comparación; no se interpreta como novedad. El fichero de seguimiento registra las revisiones y los errores para no repetir todo el histórico en cada pasada.

**Supervisión:** revisar las ejecuciones de GitHub Actions, las fuentes con errores y las entradas con `pendingEvidence`. Para actualizar una ficha publicada es necesaria una verificación editorial y mantener coherentes `incidents.js`, `incidents.json` y `feed.xml`. El fichero de seguimiento registra señales, no certifica una revisión editorial.
