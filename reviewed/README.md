# Fichas aprobadas para publicación

El observatorio separa **avisos recopilados automáticamente**, **candidatos por revisar** y **fichas editoriales confirmadas**.

## Procedimiento de publicación

1. Consulta `incident-review-queue.json` y la fuente original del candidato. No interpretes la puntuación como verificación de un incidente.
2. Contrasta hechos, fechas, ámbito, afectación, datos expuestos y recomendaciones con fuentes primarias y deja constancia de las discrepancias. Un CVE debe permanecer en Advisories si no existe un incidente real confirmado.
3. Prepara una ficha JSON en `reviewed/<identificador>.json`, revisada y aprobada por una persona con acceso de escritura al repositorio.
4. Ejecuta manualmente **Publicar ficha editorial aprobada** en GitHub Actions indicando la ruta exacta.
5. El script valida campos obligatorios, fuentes HTTPS, ausencia de coincidencias exactas y coherencia del inventario; actualiza `incidents.json`, `incidents.js`, `feed.xml` y los RSS especializados. Después se ejecuta el validador general.

La publicación requiere que en el JSON consten `approved: true`, `reviewedBy` (identificador del editor) y `reviewedAt` (fecha YYYY-MM-DD). Estos campos son metadatos de revisión, **no sustituyen la comprobación real de las fuentes**.

Ejemplo de estructura (datos ficticios, NO publicables directamente):

```json
{
  "id": "2026-11-ejemplo-revisado",
  "date": "2026-11-09",
  "title": "Ejemplo no publicable: sustituir por un título verificado",
  "organization": "Empresa de ejemplo",
  "type": "brecha",
  "severity": "alta",
  "status": "confirmado",
  "incidentState": "investigacion",
  "geo": "global",
  "scope": "Ámbito documentado",
  "lead": "Resumen factual y concreto respaldado por una comunicación oficial comprobada.",
  "summary": "Descripción detallada que explique los hechos verificados y lo que sigue por confirmar, sin asumir una exfiltración.",
  "whyItMatters": "Explicación comprobable del impacto real para las personas potencialmente afectadas.",
  "affected": "Grupo potencialmente afectado, conforme al comunicado oficial.",
  "actions": ["Consultar la comunicación original de la organización y seguir sus indicaciones oficiales."],
  "sources": [{"label": "Comunicación primaria revisada", "url": "https://example.org/comunicado", "kind": "Fuente oficial"}],
  "approved": false,
  "reviewedBy": "",
  "reviewedAt": ""
}
```

**Nunca conviertas el ejemplo en una ficha real.** Antes de su publicación hay que reemplazarlo por evidencia real y obtener aprobación editorial.

Los workflows automáticos de feeds continúan sin modificar las fichas. La aprobación es un paso separado y explícito.
