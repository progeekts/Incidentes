(() => {
  const root = document.getElementById("candidateReview");
  if (!root) return;
  const esc = v => String(v ?? "").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const names={brecha:"Posible brecha",vulnerabilidad:"Vulnerabilidad",fraude:"Fraude",malware:"Malware",otro:"Sin clasificar"};
  const date = s => {const d=new Date(s+"T12:00:00Z");return Number.isNaN(d.getTime())?s:new Intl.DateTimeFormat("es-ES",{day:"numeric",month:"short",year:"numeric",timeZone:"UTC"}).format(d)};
  fetch("incident-candidates.json",{cache:"no-store"}).then(r=>{if(!r.ok)throw Error("Archivo no disponible");return r.json()}).then(data=>{
    const items=(data.items||[]).slice(0,12);
    root.innerHTML='<div class="intel-list-head"><div><p class="eyebrow">COLA DE REVISIÓN · AUTOMÁTICA</p><h2>Avisos pendientes de verificar</h2><p>Señales procedentes de organismos oficiales. No se contabilizan como incidentes confirmados.</p></div><small>'+esc(data.count||0)+' avisos candidatos</small></div>'+
      '<div class="candidate-list">'+items.map(i=>'<a href="'+esc(i.sourceUrl)+'" target="_blank" rel="noopener noreferrer" class="candidate-row"><span><small>'+esc(i.source)+' · '+esc(date(i.published))+' · '+esc(names[i.categoryHint]||"Aviso")+'</small><strong>'+esc(i.title)+'</strong></span><span class="candidate-status">Sin verificar ↗</span></a>').join("")+'</div>'+
      (items.length?'':'<p>No hay avisos pendientes en la última recopilación.</p>')+
      '<p class="candidate-note">La clasificación es orientativa. Una vulnerabilidad publicada no implica explotación, y un aviso de brecha no acredita por sí solo exfiltración de datos.</p>';
  }).catch(()=>root.innerHTML='<h2>Avisos pendientes de verificar</h2><p>La cola de revisión automática todavía no está disponible.</p>');
})();