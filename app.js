const incidents = Array.isArray(window.INCIDENTS) ? window.INCIDENTS : [];
const list = document.getElementById('incidentList');
const summary = document.getElementById('summary');
const search = document.getElementById('search');
const typeFilter = document.getElementById('typeFilter');
const severityFilter = document.getElementById('severityFilter');
const lastUpdated = document.getElementById('lastUpdated');
const lastReview = document.getElementById('lastReview');

const labels = {
  fraude: 'Fraude / phishing',
  brecha: 'Brecha de datos',
  vulnerabilidad: 'Vulnerabilidad',
  malware: 'Malware',
  otro: 'Otro',
  critica: 'Crítica',
  alta: 'Alta',
  media: 'Media'
};

function esc(value='') {
  return String(value).replace(/[&<>'"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
}

function renderSummary(items) {
  const severe = items.filter(x => ['critica','alta'].includes(x.severity)).length;
  const breaches = items.filter(x => x.type === 'brecha').length;
  const vulns = items.filter(x => x.type === 'vulnerabilidad').length;
  summary.innerHTML = `
    <div class="stat"><strong>${items.length}</strong><span>Incidentes visibles</span></div>
    <div class="stat"><strong>${severe}</strong><span>Alta o crítica</span></div>
    <div class="stat"><strong>${breaches}</strong><span>Brechas de datos</span></div>
    <div class="stat"><strong>${vulns}</strong><span>Vulnerabilidades</span></div>`;
}

function render() {
  const q = search.value.trim().toLowerCase();
  const t = typeFilter.value;
  const s = severityFilter.value;
  const filtered = incidents
    .filter(i => t === 'all' || i.type === t)
    .filter(i => s === 'all' || i.severity === s)
    .filter(i => !q || [i.title,i.organization,i.lead,i.reportedScale,i.summary,i.scope,i.affected].join(' ').toLowerCase().includes(q))
    .sort((a,b) => b.date.localeCompare(a.date));

  renderSummary(filtered);

  if (!filtered.length) {
    list.innerHTML = '<div class="empty">No hay incidentes que coincidan con estos filtros.</div>';
    return;
  }

  list.innerHTML = filtered.map(i => `
    <article class="incident">
      <div class="incident-top">
        <div>
          <div class="badges">
            <span class="badge sev-${esc(i.severity)}">${esc(labels[i.severity] || i.severity)}</span>
            <span class="badge">${esc(labels[i.type] || i.type)}</span>
            <span class="badge">${esc(i.status)}</span>
          </div>
          <h3>${esc(i.title)}</h3>
          <div class="meta">${esc(i.date)} · ${esc(i.organization)} · ${esc(i.scope)}</div>
          ${i.lead ? `<p class="incident-lead">${esc(i.lead)}</p>` : ''}
          ${i.reportedScale ? `<div class="scale-callout"><span>${esc(i.reportedScaleStatus || 'Alcance reportado')}</span><strong>${esc(i.reportedScale)}</strong></div>` : ''}
        </div>
      </div>
      <div class="incident-grid">
        <div class="info-box"><h4>Qué ocurrió</h4><p>${esc(i.summary)}</p></div>
        <div class="info-box"><h4>Por qué importa</h4><p>${esc(i.whyItMatters)}</p></div>
        <div class="info-box"><h4>Quién puede estar afectado</h4><p>${esc(i.affected)}</p></div>
        <div class="info-box"><h4>Qué hacer ahora</h4><ul class="actions">${(i.actions||[]).map(a => `<li>${esc(a)}</li>`).join('')}</ul></div>
      </div>
      ${i.notes ? `<div class="sources"><strong>Contexto de verificación:</strong> ${esc(i.notes)}</div>` : ''}
      <div class="sources"><strong>Fuentes:</strong> ${(i.sources||[]).map(src => `<a href="${esc(src.url)}" target="_blank" rel="noopener noreferrer">${esc(src.label)}</a>`).join('')}</div>
    </article>`).join('');
}

[search,typeFilter,severityFilter].forEach(el => el.addEventListener('input', render));
lastUpdated.textContent = `Última publicación: ${window.INCIDENT_META?.lastUpdated || 'sin fecha'}`;
if (lastReview) lastReview.textContent = window.INCIDENT_META?.lastReview || 'Pendiente de registrar';
render();
