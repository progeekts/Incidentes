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
