(() => {
"use strict";
const $=id=>document.getElementById(id);
const root=$("threatConsole");
if(!root)return;
const esc=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const parseDate=x=>{
  const s=String(x||"").replace(/ CEST$/," +0200").replace(/ CET$/," +0100");
  const d=Date.parse(s.length===10?s+"T12:00:00Z":s);
  return Number.isFinite(d)?d:0;
};
const fmtDate=(x,opts={day:"2-digit",month:"short"})=>{
 const d=parseDate(x);return d?new Intl.DateTimeFormat("es-ES",{...opts,timeZone:"Europe/Madrid"}).format(new Date(d)):"—";
};
const incidents=Array.isArray(window.INCIDENTS)?window.INCIDENTS:[];
const typeNames={brecha:"Brechas",vulnerabilidad:"Vulnerabilidades",malware:"Malware",fraude:"Fraude",otro:"Otros"};
const stateNames={investigacion:"Investigación",activo:"Activo",seguimiento:"Seguimiento",contenido:"Contenido",resuelto:"Resuelto"};
const sevColors={critica:"#ff5378",alta:"#ffaf55",media:"#37cdb7",otro:"#71829a"};
function metric(id,value){const el=$(id);if(el)el.textContent=String(value);}
const total=incidents.length;
metric("opsIncidentCount",total);
metric("opsBreaches",incidents.filter(i=>i.type==="brecha").length);
metric("opsUnderReview",incidents.filter(i=>i.incidentState==="investigacion"||i.incidentState==="activo").length);
function plotLine(data){
 const svg=$("opsTrendChart"),labels=$("opsTrendLabels"),caption=$("opsTrendCaption");
 if(!svg)return;
 const W=720,H=190,pad=16,max=Math.max(1,...data.map(x=>x.y));
 const pts=data.map((o,i)=>[pad+i*(W-pad*2)/Math.max(1,data.length-1),H-24-(o.y/max)*(H-57)]);
 const line=pts.map((p,i)=>(i?"L":"M")+p[0].toFixed(1)+" "+p[1].toFixed(1)).join(" ");
 const area=line+" L "+pts[pts.length-1][0].toFixed(1)+" "+(H-24)+" L "+pad+" "+(H-24)+" Z";
 const grid=[0,1,2,3].map(i=>{let y=H-24-i*(H-57)/3;return '<line x1="16" y1="'+y.toFixed(1)+'" x2="704" y2="'+y.toFixed(1)+'" stroke="#263853" stroke-dasharray="3 5" /><text x="5" y="'+(y-4).toFixed(1)+'" fill="#8a9bb0" font-size="9">'+Math.round(i*max/3)+'</text>'}).join("");
 svg.innerHTML='<defs><linearGradient id="opsAreaGradient" x1="0" x2="0" y1="0" y2="1"><stop stop-color="#2ad9e9" stop-opacity=".27"/><stop offset="1" stop-color="#2ad9e9" stop-opacity=".005"/></linearGradient></defs>'+grid+
 '<path d="'+area+'" fill="url(#opsAreaGradient)"/><path d="'+line+'" fill="none" stroke="#27e0ed" stroke-width="2.8" stroke-linejoin="round" stroke-linecap="round"/>'+
 pts.filter((p,i)=>i%7===0||i===pts.length-1).map(p=>'<circle cx="'+p[0]+'" cy="'+p[1]+'" r="3" fill="#27e0ed" stroke="#101b30" stroke-width="2"/>').join("");
 labels.innerHTML='<span>'+fmtDate(data[0]?.date)+'</span><span>'+fmtDate(data[Math.floor((data.length-1)/2)]?.date)+'</span><span>'+fmtDate(data[data.length-1]?.date)+'</span>';
 if(caption)caption.textContent="Advisories publicados por día · "+data.reduce((a,b)=>a+b.y,0)+" en el periodo mostrado";
}
function trend(items,period="30"){
 const windowDays=period==="7"?7:period==="90"?90:30;
 const days=[];
 const today=new Date();today.setUTCHours(12,0,0,0);
 const counts={};
 for(const a of items){const day=/^\d{4}-\d{2}-\d{2}$/.test(a.published||"")?a.published:"";if(day)counts[day]=(counts[day]||0)+1;}
 for(let n=windowDays-1;n>=0;n--){const t=new Date(today);t.setUTCDate(today.getUTCDate()-n);const k=t.toISOString().slice(0,10);days.push({date:k,y:counts[k]||0});}
 plotLine(days);
}
function sevDonut(items=incidents){
 const counts=["critica","alta","media"].map(k=>({k,v:items.filter(i=>i.severity===k).length}));
 const other=items.length-counts.reduce((s,x)=>s+x.v,0);
 if(other)counts.push({k:"otro",v:other});
 let offset=0;const circumference=2*Math.PI*44;
 $("opsDonutSegments").innerHTML=counts.map(x=>{
  const portion=items.length?x.v/items.length:0;
  const dash=portion*circumference;
  const html='<circle cx="60" cy="60" r="44" fill="none" stroke="'+sevColors[x.k]+'" stroke-width="13" stroke-dasharray="'+dash.toFixed(2)+' '+(circumference-dash).toFixed(2)+'" stroke-dashoffset="'+(-offset).toFixed(2)+'" />';
  offset+=dash;return html;
 }).join("");
 $("opsDonutLabel").textContent=String(items.length);
 $("opsSeverityLegend").innerHTML=counts.map(x=>'<div class="ops-legend-row"><i style="background:'+sevColors[x.k]+'"></i><span>'+esc(({critica:"Crítica",alta:"Alta",media:"Media",otro:"Otros"})[x.k])+'</span><b>'+x.v+'</b></div>').join("");
}
function types(items=incidents){
 const counts=Object.entries(typeNames).map(([key,label])=>({key,label,count:items.filter(i=>i.type===key).length}));
 const max=Math.max(1,...counts.map(x=>x.count));
 $("opsTypeBars").innerHTML=counts.map((x,i)=>'<div class="ops-bar-row"><span>'+esc(x.label)+'</span><div class="ops-bar-track"><i style="width:'+(x.count/max*100).toFixed(1)+'%;background:'+["#24d7e7","#697dff","#fc507e","#ff9a51","#8495aa"][i]+'"></i></div><b>'+x.count+'</b></div>').join("");
}
function actions(items){
 const sorted=items.filter(a=>a.exploited).sort((a,b)=>parseDate(b.published)-parseDate(a.published));
 const shown=(sorted.length?sorted:items.filter(a=>a.severity==="critical").sort((a,b)=>parseDate(b.published)-parseDate(a.published))).slice(0,4);
 $("opsPriorityList").innerHTML=shown.length?shown.map(a=>{
  const url=/^https:\/\//.test(a.url||"")?a.url:"#";
  return '<a class="ops-priority-row" href="'+esc(url)+'" target="_blank" rel="noopener noreferrer"><span class="ops-priority-indicator '+(a.exploited?"ops-critical":"ops-high")+'"></span><span class="ops-priority-body"><strong>'+esc(a.cve||a.id||"Advisory")+'</strong><small>'+esc(a.product||a.ecosystem||"Producto no especificado")+'</small></span><span class="ops-priority-tag">'+(a.exploited?"KEV":"Crítica")+'</span></a>';
 }).join(""):'<p class="ops-muted">Sin advisories prioritarios disponibles.</p>';
}
function liveRows(candidates){
 const arr=[...candidates].sort((a,b)=>parseDate(b.published)-parseDate(a.published)).slice(0,7);
 $("opsSignalsTable").innerHTML=arr.length?arr.map(a=>{
  const safe=/^https:\/\//.test(a.sourceUrl||"")?a.sourceUrl:"#";
  const category=typeNames[a.categoryHint]||"Aviso";
  return '<tr><td class="ops-date">'+esc(fmtDate(a.published))+'</td><td><a href="'+esc(safe)+'" target="_blank" rel="noopener noreferrer">'+esc(a.title)+'</a><small>'+esc(a.source)+'</small></td><td><span class="ops-type">'+esc(category)+'</span></td><td><span class="ops-wait">Por verificar</span></td></tr>';
 }).join(""):'<tr><td colspan="4">Sin señales pendientes.</td></tr>';
}
function setStatus(a,s,c){
 const times=[a?.lastReview,s?.lastReview,c?.lastGenerated].map(parseDate).filter(Boolean);
 const latest=times.length?Math.max(...times):0;
 const ok=latest&&Date.now()-latest<36*3600000;
 const state=$("opsSyncState");
 state.textContent=ok?"SINCRONIZADO":"DATOS ATRASADOS";
 state.className="ops-status "+(ok?"ops-status-good":"ops-status-warn");
 $("opsSyncTime").textContent=latest?new Intl.DateTimeFormat("es-ES",{day:"numeric",month:"short",hour:"2-digit",minute:"2-digit",timeZone:"Europe/Madrid"}).format(new Date(latest))+" · Madrid":"Sin fecha";
 const available=Object.values(s?.status||{}).filter(x=>x.ok).length;
 const expected=Object.keys(s?.status||{}).length;
 $("opsSourcesLabel").textContent=expected?available+"/"+expected+" fuentes":"Fuentes no disponibles";
}
sevDonut();types();
Promise.allSettled(["advisories.json","source-alerts.json","incident-candidates.json"].map(p=>fetch(p,{cache:"no-store"}).then(r=>{if(!r.ok)throw Error(p);return r.json()})))
.then(([ra,rs,rc])=>{
 const a=ra.status==="fulfilled"?ra.value:null;
 const s=rs.status==="fulfilled"?rs.value:null;
 const c=rc.status==="fulfilled"?rc.value:null;
 const items=Array.isArray(a?.items)?a.items:[];
 const candidates=Array.isArray(c?.items)?c.items:[];
 metric("opsAdvisories",items.length);
 metric("opsKnownExploited",items.filter(x=>x.exploited).length);
 metric("opsCandidates",candidates.length);
 metric("opsCriticalAdvisories",items.filter(x=>x.severity==="critical").length);
 setStatus(a,s,c);
 window.ThreatData={incidents,advisories:items,candidates,feeds:Array.isArray(s?.items)?s.items:[]};
 window.renderThreatFiltered=function(filters={}){
  const period=filters.period||"all",days=period==="all"?null:Number(period);
  const min=days?Date.now()-days*86400000:0;
  const severity=filters.severity||"all",geo=filters.geo||"all";
  const inc=incidents.filter(i=>(geo==="all"||i.geo===geo)&&(severity==="all"||i.severity===severity)&&(!min||parseDate(i.date)>=min));
  const severityMap={critica:"critical",alta:"high",media:"moderate"};
  const adv=items.filter(i=>(severity==="all"||i.severity===severityMap[severity]||(severity==="media"&&i.severity==="medium"))&&(!min||parseDate(i.published)>=min));
  const cand=candidates.filter(i=>!min||parseDate(i.published)>=min);
  metric("opsIncidentCount",inc.length);
  metric("opsBreaches",inc.filter(i=>i.type==="brecha").length);
  metric("opsUnderReview",inc.filter(i=>i.incidentState==="investigacion"||i.incidentState==="activo").length);
  metric("opsAdvisories",adv.length);
  metric("opsKnownExploited",adv.filter(i=>i.exploited).length);
  metric("opsCandidates",cand.length);
  metric("opsCriticalAdvisories",adv.filter(i=>i.severity==="critical").length);
  const trendHeader=document.querySelector('.ops-trend .ops-panel-meta');
  if(trendHeader)trendHeader.textContent=period==='all'?'ÚLTIMOS 30 DÍAS':`ÚLTIMOS ${period} DÍAS`;
  sevDonut(inc);types(inc);trend(adv,period);actions(adv);liveRows(cand);
  document.dispatchEvent(new CustomEvent("threat:filters-rendered",{detail:{filters,incidents:inc,advisories:adv,candidates:cand}}));
 };
 window.renderThreatFiltered(window.ThreatFilters||{});
 document.dispatchEvent(new CustomEvent("threat:data-ready",{detail:window.ThreatData}));
 $("opsDataNote").textContent="Los gráficos de severidad y tipo reflejan únicamente el inventario editorial. Las señales pendientes y los advisories proceden de catálogos externos.";
}).catch(()=>{
 $("opsDataNote").textContent="No se han podido cargar todos los datos; comprueba la última sincronización.";
});
})();