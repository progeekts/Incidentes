window.INCIDENTS = [
  {
    id: "2026-09-idscan",
    date: "2026-09-04",
    title: "Incidente de seguridad en IDScan.net",
    organization: "IDScan.net",
    type: "brecha",
    severity: "alta",
    status: "confirmado",
    scope: "Principalmente Estados Unidos y Canadá",
    summary: "IDScan.net publicó una notificación sobre un incidente de seguridad que afecta a su entorno de verificación de identidad. La empresa trabaja con documentos como permisos de conducir, documentos de identidad y pasaportes.",
    whyItMatters: "Los datos usados para verificar identidad pueden ser especialmente sensibles y útiles para intentos posteriores de suplantación o phishing dirigido.",
    affected: "Personas cuyos documentos hayan sido procesados a través de organizaciones que utilizan servicios de IDScan.net. El alcance individual debe confirmarse mediante comunicaciones oficiales.",
    actions: [
      "Revisa cualquier notificación oficial que recibas de una empresa donde hayas verificado tu identidad.",
      "Desconfía de mensajes que usen datos personales correctos para aparentar legitimidad.",
      "Contacta con la organización por sus canales oficiales si recibes una comunicación sospechosa.",
      "Vigila movimientos o altas de servicios que no reconozcas si sabes que tus datos han estado expuestos."
    ],
    sources: [
      { label: "Notificación oficial de IDScan.net", url: "https://www.idscan.net/security-incident-notice/" }
    ],
    notes: "Las cifras difundidas por terceros sobre el volumen exacto de documentos afectados deben considerarse no confirmadas hasta que exista respaldo oficial verificable."
  }
];

window.INCIDENT_META = {
  lastUpdated: "2026-09-16",
  lastReview: "16 de septiembre de 2026 · 08:24 (CEST)",
  methodology: "Solo se incluyen incidentes con impacto material potencial para usuarios cotidianos y con fuentes verificables."
};
