window.INCIDENTS = [
  {
    id: "2026-09-idscan",
    date: "2026-09-04",
    title: "Filtración vinculada a IDScan.net expone millones de documentos de identidad",
    organization: "IDScan.net",
    type: "brecha",
    severity: "alta",
    status: "confirmado",
    scope: "Principalmente Estados Unidos y Canadá",
    lead: "Un servicio criminal afirmó disponer de más de 153 millones de registros de permisos de conducir, además de otros documentos de identidad. IDScan.net confirmó que un tercero no autorizado pudo acceder o copiar información almacenada en cuentas de clientes de su nube.",
    reportedScale: "Más de 153 millones de registros de permisos de conducir anunciados por el servicio criminal; la cifra no equivale a un recuento oficialmente confirmado de personas afectadas.",
    reportedScaleStatus: "Cifra reportada · alcance exacto no confirmado",
    summary: "IDScan.net informó de que un tercero no autorizado pudo haber accedido o copiado determinada información de clientes almacenada en su nube. Investigaciones periodísticas relacionaron el incidente con una colección de documentos de identidad ofrecida por un servicio criminal. El FBI está investigando el caso.",
    whyItMatters: "Las imágenes y datos de documentos oficiales pueden facilitar suplantaciones de identidad, fraude y campañas de phishing muy convincentes. A diferencia de una contraseña, un documento de identidad no puede sustituirse con la misma facilidad.",
    affected: "Personas cuyos documentos hayan sido procesados a través de organizaciones que utilizan servicios de IDScan.net, principalmente en Estados Unidos y Canadá. El número exacto de personas afectadas no está confirmado públicamente.",
    actions: [
      "Revisa cualquier notificación oficial que recibas de una empresa donde hayas verificado tu identidad.",
      "Desconfía de mensajes que usen datos personales correctos para aparentar legitimidad.",
      "Contacta con la organización por sus canales oficiales si recibes una comunicación sospechosa.",
      "Vigila movimientos o altas de servicios que no reconozcas si sabes que tus datos han estado expuestos."
    ],
    sources: [
      { label: "Notificación oficial de IDScan.net", url: "https://idscan.net/press-release/notification-of-data-security-incident/" },
      { label: "Reuters · investigación del FBI", url: "https://www.reuters.com/world/us/fbi-says-it-is-investigating-report-that-millions-us-drivers-licenses-exposed-2026-09-02/" }
    ],
    notes: "La existencia del incidente y la posible copia no autorizada de información han sido reconocidas por IDScan.net. La cifra de más de 153 millones procede del conjunto anunciado por el servicio criminal y de investigaciones posteriores; no debe interpretarse como 153 millones de víctimas únicas confirmadas."
  }
];

window.INCIDENT_META = {
  lastUpdated: "2026-09-16",
  lastReview: "16 de septiembre de 2026 · 08:24 (CEST)",
  methodology: "Solo se incluyen incidentes con impacto material potencial para usuarios cotidianos y con fuentes verificables."
};
