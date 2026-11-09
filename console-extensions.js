(() => {
"use strict";
const $=id=>document.getElementById(id);
if(!$("globalPeriod"))return;
const esc=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const safe=s=>/^https:\/\/[^ ]+$/i.test(s||"")?s:"#";
const parseDate=s=>{const n=Date.parse(String(s||"").length===10?s+"T12:00:00Z":s);return Number.isFinite(n)?n:0};
const date=s=>{const t=parseDate(s);return t?new Intl.DateTimeFormat("es-ES",{day:"numeric",month:"short",year:"numeric",timeZone:"Europe/Madrid"}).format(new Date(t)):"Sin fecha"};
const data={incidents:[],advisories:[],candidates:[],queue:[]};
let filters={geo:"all",severity:"all",period:"30"};
window.ThreatFilters=filters;
const storageKey="alertascibersec:watch-v1";
let watched=[];
try{const stored=JSON.parse(localStorage.getItem(storageKey)||"[]");watched=Array.isArray(stored)?stored.filter(x=>typeof x==="string").slice(0,25):[]}catch(e){}
const standard=["PHP","Node.js","Brotli","Windows","Cisco","Fortinet","GitLab","Apache","Linux"];
function store(){try{localStorage.setItem(storageKey,JSON.stringify(watched))}catch(e){}}
function setFilters(){
 filters={geo:$("globalGeo").value,severity:$("globalSeverity").value,period:$("globalPeriod").value};
 window.ThreatFilters=filters;
 if(typeof window.renderThreatFiltered==="function")window.renderThreatFiltered(filters);
 document.dispatchEvent(new CustomEvent("threat:filters-changed",{detail:filters}));
 draw();
}
["globalGeo","globalSeverity","globalPeriod"].forEach(id=>$(id).addEventListener("change",setFilters));
$("globalReset").addEventListener("click",()=>{
 $("globalGeo").value="all";$("globalSeverity").value="all";$("globalPeriod").value="30";setFilters();
});
function insidePeriod(d){
 if(filters.period==="all")return true;
 const t=parseDate(d);
 return t&&t>=Date.now()-Number(filters.period)*86400000;
}
function appliesSeverity(item,isAdvisory=false){
 if(filters.severity==="all")return true;
 const matched=isAdvisory?{critica:["critical"],alta:["high"],media:["moderate","medium"]}[filters.severity]:[filters.severity];
 return matched.includes(item.severity);
}
function currentIncidents(){return data.incidents.filter(i=>(filters.geo==="all"||i.geo===filters.geo)&&appliesSeverity(i)&&insidePeriod(i.date))}
function currentAdvisories(){return data.advisories.filter(a=>appliesSeverity(a,true)&&insidePeriod(a.published))}
function currentCandidates(){return data.candidates.filter(i=>insidePeriod(i.published))}
function renderAttention(){
 const inc=currentIncidents();
 const adv=currentAdvisories().filter(a=>a.exploited);
 const items=[
 ...adv.map(a=>({priority:3,date:a.published,title:a.cve||a.id,subtitle:a.product||"Software",text:"Explotación conocida según CISA KEV. Comprueba las versiones afectadas y la actualización oficial.",url:safe(a.url),tag:"KEV · EXPLOTADA",kind:"critical"})),
 ...inc.filter(i=>i.incidentState==="activo"||i.incidentState==="investigacion").map(i=>({priority:i.severity==="critica"?2:1,date:i.date,title:i.title,subtitle:i.organization,text:i.affected||i.lead||i.summary,url:"incidente/?id="+encodeURIComponent(i.id)+"#acciones",tag:i.incidentState==="activo"?"ACTIVO":"EN INVESTIGACIÓN",kind:"notice"}))
 ];
 items.sort((a,b)=>b.priority-a.priority||parseDate(b.date)-parseDate(a.date));
 $("attentionCount").textContent=items.length+" elementos · primeros 5";
 $("attentionItems").innerHTML=items.length?items.slice(0,5).map(x=>'<a class="ops-attention-item '+x.kind+'" href="'+esc(x.url)+'" '+(x.url.startsWith("https:")?'target="_blank" rel="noopener noreferrer"':'')+'><span class="ops-attention-level">'+esc(x.tag)+'</span><span class="ops-attention-content"><strong>'+esc(x.title)+'</strong><small>'+esc(x.subtitle)+' · '+esc(date(x.date))+'</small><span>'+esc(x.text).slice(0,230)+'</span></span><span class="ops-attention-open">↗</span></a>').join(""):'<p class="ops-muted">No hay prioridades documentadas para los filtros seleccionados.</p>';
}
function renderTimeline(){
 const entries=[
 ...currentIncidents().map(i=>({date:i.date,title:i.title,kind:"Incidente documentado",url:"incidente/?id="+encodeURIComponent(i.id),color:"incident"})),
 ...currentAdvisories().map(a=>({date:a.published,title:(a.cve?a.cve+" · ":"")+(a.title||a.product),kind:a.exploited?"CISA KEV":"Advisory",url:safe(a.url),color:a.exploited?"kev":"advisory"}))
 ];
 entries.sort((a,b)=>parseDate(b.date)-parseDate(a.date));
 $("opsTimeline").innerHTML=entries.length?entries.slice(0,12).map(e=>'<div class="ops-timeline-entry"><span class="ops-timeline-dot '+e.color+'"></span><span class="ops-timeline-date">'+esc(date(e.date))+'</span><div><small>'+esc(e.kind)+'</small><a href="'+esc(e.url)+'" '+(e.url.startsWith("https:")?'target="_blank" rel="noopener noreferrer"':'')+'>'+esc(e.title)+'</a></div></div>').join(""):'<p class="ops-muted">Sin eventos documentados en este periodo.</p>';
}
function matching(a,tech){
 const hay=[a.product,a.ecosystem,a.title,a.summary].join(" ").toLocaleLowerCase("es");
 return hay.includes(tech.toLocaleLowerCase("es"));
}
function renderWatch(){
 const chosen=[...new Set([...standard,...watched])];
 $("watchChoices").innerHTML=chosen.map(x=>'<button type="button" class="ops-watch-chip '+(watched.includes(x)?"selected":"")+'" data-tech="'+esc(x)+'" aria-pressed="'+watched.includes(x)+'">'+esc(x)+(watched.includes(x)?" ×":" +")+'</button>').join("");
 $("watchCount").textContent=watched.length+" SEGUIDAS";
 const filtered=currentAdvisories().filter(a=>watched.some(t=>matching(a,t))).sort((a,b)=>Number(b.exploited)-Number(a.exploited)||parseDate(b.published)-parseDate(a.published));
 $("watchResults").innerHTML=watched.length?('<h4>'+filtered.length+' advisories relacionados</h4>'+(filtered.length?filtered.slice(0,8).map(a=>'<a class="ops-watch-result" target="_blank" rel="noopener noreferrer" href="'+esc(safe(a.url))+'"><span>'+esc(a.cve||a.id)+'</span><strong>'+esc(a.title||a.product)+'</strong>'+(a.exploited?'<em>KEV</em>':'')+'</a>').join(""):'<p class="ops-muted">Sin coincidencias en el catálogo y periodo seleccionados.</p>')):'<p class="ops-muted">Selecciona una tecnología para mostrar sus avisos.</p>';
 $("watchChoices").querySelectorAll("button").forEach(b=>b.addEventListener("click",()=>{
  const tech=b.getAttribute("data-tech");
  watched=watched.includes(tech)?watched.filter(x=>x!==tech):[...watched,tech].slice(0,25);
  store();renderWatch();
 }));
}
$("watchForm").addEventListener("submit",e=>{
 e.preventDefault();
 const val=$("watchCustom").value.trim().replace(/[<>]/g,"").slice(0,45);
 if(val&&!watched.some(x=>x.toLowerCase()===val.toLowerCase()))watched=[...watched,val].slice(0,25);
 $("watchCustom").value="";store();renderWatch();
});
async function loadQueue(){
 try{
  const res=await fetch("incident-review-queue.json",{cache:"no-store"});
  if(!res.ok)throw Error("No disponible");
  const json=await res.json();data.queue=Array.isArray(json.items)?json.items:[];
 }catch(e){data.queue=[];}
 renderQueue();
}
function renderQueue(){
 const rows=data.queue.filter(x=>insidePeriod(x.published)).sort((a,b)=>b.score-a.score||parseDate(b.published)-parseDate(a.published)).slice(0,6);
 $("reviewQueueItems").innerHTML=rows.length?rows.map(q=>'<div class="ops-review-row"><span class="ops-review-score">'+esc(q.score)+'/100</span><div><strong>'+esc(q.title)+'</strong><small>'+esc(q.source)+' · '+esc(date(q.published))+'</small><p>'+esc(q.reason||"Candidato pendiente de contrastar")+'</p></div><span class="ops-review-state">'+esc(q.status||"Revisión necesaria")+'</span><a href="'+esc(safe(q.sourceUrl))+'" target="_blank" rel="noopener noreferrer">Fuente ↗</a><a href="https://github.com/progeekts/Incidentes/issues/new" target="_blank" rel="noopener noreferrer">Revisar ↗</a></div>').join(""):'<p class="ops-muted">La cola de preevaluación está pendiente de generación o no hay candidatos en este periodo.</p>';
}
function draw(){
 const panels=[
   ["attentionItems",renderAttention],
   ["opsTimeline",renderTimeline],
   ["watchResults",renderWatch],
   ["reviewQueueItems",renderQueue]
 ];
 panels.forEach(([id,fn])=>{
   try{fn()}catch(error){
     console.error("Error al mostrar "+id,error);
     const el=$(id);
     if(el)el.innerHTML='<p class="ops-muted">Este módulo no se ha podido mostrar. Recarga la página para reintentarlo.</p>';
   }
 });
}
let started=false;
function hydrate(payload){
 const d=payload||{};
 data.incidents=Array.isArray(d.incidents)?d.incidents:[];
 data.advisories=Array.isArray(d.advisories)?d.advisories:[];
 data.candidates=Array.isArray(d.candidates)?d.candidates:[];
 draw();
 if(!started){started=true;loadQueue();}
}
document.addEventListener("threat:data-ready",e=>hydrate(e.detail));
if(window.ThreatData){
 hydrate(window.ThreatData);
}else{
 // Funciona también si el evento del dashboard se ha emitido antes de instalar
 // este listener o si el navegador ha cargado los scripts desde cachés distintas.
 Promise.allSettled([
   fetch("advisories.json",{cache:"no-store"}).then(r=>{if(!r.ok)throw Error("advisories");return r.json()}),
   fetch("incident-candidates.json",{cache:"no-store"}).then(r=>{if(!r.ok)throw Error("candidates");return r.json()})
 ]).then(([a,c])=>hydrate({
   incidents:Array.isArray(window.INCIDENTS)?window.INCIDENTS:[],
   advisories:a.status==="fulfilled"?a.value.items:[],
   candidates:c.status==="fulfilled"?c.value.items:[]
 })).catch(error=>{
   console.error("No se han podido recuperar los módulos de seguimiento",error);
   hydrate({incidents:window.INCIDENTS||[],advisories:[],candidates:[]});
 });
}
})();