(() => {
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const items=(Array.isArray(window.INCIDENTS)?window.INCIDENTS:[]).filter(i=>i.type==="brecha");
const date=d=>{if(!d)return "Sin fecha";const x=new Date(d+"T12:00:00Z");return Number.isNaN(x.getTime())?d:new Intl.DateTimeFormat("es-ES",{day:"numeric",month:"short",year:"numeric",timeZone:"Europe/Madrid"}).format(x)};
const states={investigacion:"En investigación",activo:"Activo",contenido:"Contenido",resuelto:"Resuelto",seguimiento:"Seguimiento"};
const card=i=>'<article class="intel-card"><header><span class="intel-chip '+(i.severity==="critica"?"critical":i.severity==="alta"?"high":"")+'">'+esc(i.severity||"Sin gravedad")+'</span><span class="intel-chip">'+esc(states[i.incidentState]||i.incidentState||"Sin estado")+'</span></header>'+
'<h3>'+esc(i.title)+'</h3><p class="detail"><b>Organización:</b> '+esc(i.organization)+'</p>'+
'<p class="desc">'+esc(i.lead||i.summary)+'</p>'+
'<p class="detail"><b>Datos afectados o investigados:</b> '+esc((i.dataTypes||[]).join(", ")||"Por determinar")+'</p>'+
'<p class="detail"><b>Alcance comunicado:</b> '+esc(i.reportedScale||"Sin cifras confirmadas")+'</p>'+
'<p class="detail"><b>Situación:</b> '+esc(i.reportedScaleStatus||"Consultar fuentes de la ficha")+'</p>'+
'<div class="foot"><span>'+esc(date(i.date))+' · '+esc(i.geo||"Ámbito no especificado")+'</span><a href="incidente/?id='+encodeURIComponent(i.id)+'">Ver ficha y fuentes ↗</a></div></article>';
$("bTotal").textContent=items.length;
$("bInvestigating").textContent=items.filter(i=>i.incidentState==="investigacion").length;
$("bFigures").textContent=items.filter(i=>/\d[\d,.]*\s*(mill[oó]n|mil|registros|personas|cuentas)/i.test(i.reportedScale||"")).length;
$("bReview").textContent=window.INCIDENT_META?.lastUpdated||"Sin fecha";
function render(){
 const query=$("bSearch").value.trim().toLocaleLowerCase("es"),state=$("bState").value,geo=$("bGeo").value;
 const filtered=items.filter(i=>(state==="all"||i.incidentState===state)&&(geo==="all"||i.geo===geo)&&(!query||[i.organization,i.title,i.lead,i.summary,i.reportedScale,...(i.dataTypes||[])].join(" ").toLocaleLowerCase("es").includes(query)));
 filtered.sort((a,b)=>(b.date||"").localeCompare(a.date||""));
 $("bCount").textContent=filtered.length+" brechas o exposiciones documentadas";
 $("breachList").innerHTML=filtered.length?filtered.map(card).join(""):'<p class="intel-empty">No hay casos con estos filtros.</p>';
}
["bSearch","bState","bGeo"].forEach(id=>$(id).addEventListener("input",render));render();
})();