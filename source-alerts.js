(() => {
  const box = document.getElementById("sourceAlerts");
  if (!box) return;
  fetch("source-alerts.json", {cache:"no-store"}).then(r => {
    if (!r.ok) throw Error("Feed todavía no disponible");
    return r.json();
  }).then(data => {
    const esc = s => String(s || "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
    const list = (data.items || []).slice(0,8);
    const failed = Object.entries(data.status || {}).filter(([_,v])=>!v.ok).map(([k])=>k);
    let stamp = "Sin fecha";
    if (data.lastReview) {
      const d = new Date(data.lastReview);
      if (!Number.isNaN(d.getTime())) stamp = new Intl.DateTimeFormat("es-ES",{dateStyle:"medium",timeStyle:"short",timeZone:"Europe/Madrid"}).format(d);
    }
    const dateLabel = document.getElementById("lastReview");
    const reviewLabel = document.querySelector(".review-top span");
    const reviewNote = document.querySelector(".review-status small");
    if (reviewLabel) reviewLabel.textContent = "ÚLTIMA CONSULTA DE FUENTES";
    if (dateLabel) dateLabel.textContent = stamp + " (Madrid)";
    const successful = Object.values(data.status || {}).filter(v => v.ok).length;
    const total = Object.keys(data.status || {}).length;
    if (reviewNote) reviewNote.textContent = successful + " de " + total + " fuentes disponibles · incidentes verificados por separado";
    box.innerHTML = '<div style="display:flex;flex-wrap:wrap;gap:1rem;align-items:center;justify-content:space-between;margin-bottom:1rem"><div><p class="eyebrow">FUENTES OFICIALES · RECOPILACIÓN AUTOMÁTICA</p><h2 style="margin:.4rem 0">Últimos avisos de organismos</h2><p style="opacity:.75">No son incidentes verificados individualmente por este observatorio.</p></div><small>Última consulta: '+esc(stamp)+'</small></div>'+
    (failed.length?'<p role="status" style="margin-bottom:1rem">Fuentes temporalmente no disponibles: '+esc(failed.join(", "))+'. Algunos avisos pueden ser anteriores.</p>':'')+
    '<div style="display:grid;gap:.7rem">'+list.map(i=>'<a target="_blank" rel="noopener noreferrer" href="'+esc(i.url)+'" style="display:block;padding:1rem;border:1px solid #40516a;border-radius:10px;text-decoration:none;color:inherit"><small style="opacity:.75">'+esc(i.source)+' · '+esc(i.published)+'</small><strong style="display:block;margin-top:.3rem">'+esc(i.title)+' ↗</strong></a>').join("")+'</div>'+
    '<p style="opacity:.7;margin-top:1rem;font-size:.85rem">Consulta las fuentes originales. Los títulos conservan el idioma publicado por cada organismo.</p>';
  }).catch(() => {
    const dateLabel = document.getElementById("lastReview");
    const reviewLabel = document.querySelector(".review-top span");
    const reviewNote = document.querySelector(".review-status small");
    if (reviewLabel) reviewLabel.textContent = "CONSULTA AUTOMÁTICA NO DISPONIBLE";
    if (dateLabel) dateLabel.textContent = "Sin datos recientes";
    if (reviewNote) reviewNote.textContent = "No se ha podido consultar el estado de los feeds";
    box.innerHTML='<h2>Avisos de organismos oficiales</h2><p>La primera recopilación automática todavía no está disponible. Los incidentes verificados siguen accesibles.</p>';
  });
})();
