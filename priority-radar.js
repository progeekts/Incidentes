(() => {
"use strict";
const root=document.getElementById("priorityRadar");
if(!root)return;
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const safeUrl=s=>{try{const u=new URL(s);return u.protocol==="https:"?u.href:"#"}catch{return "#"}};
const prettyDate=s=>{const d=new Date((s||"").length===10?s+"T12:00:00Z":s);return Number.isNaN(d.getTime())?"Sin fecha":new Intl.DateTimeFormat("es-ES",{dateStyle:"medium",timeZone:"Europe/Madrid"}).format(d)};
const ageHours=s=>{const d=Date.parse(s||"");return Number.isFinite(d)?Math.max(0,(Date.now()-d)/3600000):Infinity};
let advisories=[],sources=[],candidates=[],lastAdvisories="",lastSources="";
const search=root.querySelector("#radarSearch");
const onlyKev=root.querySelector("#radarKevOnly");
const showRecent=root.querySelector("#radarRecentOnly");
const output=root.querySelector("#radarResults");
const status=root.querySelector("#radarStatus");
const total=root.querySelector("#radarTotal");
const countKev=root.querySelector("#radarKevCount");
const sourceCount=root.querySelector("#radarSourcesCount");
const pending=root.querySelector("#radarPendingCount");
const clear=root.querySelector("#radarClear");
const uniqueByCve=new Set();
function rank(a){
 const days=(Date.now()-Date.parse((a.published||"2000-01-01")+"T12:00:00Z"))/86400000;
 return (a.exploited?1000:0)+(a.severity==="critical"?250:a.severity==="high"?110:0)+Math.max(0,60-days);
}
function results(){
 const q=search.value.trim().toLocaleLowerCase("es");
 const cutoff=Date.now()-30*86400000;
 const matches=advisories.filter(a=>{
  const text=[a.cve,a.id,a.title,a.product,a.ecosystem,a.summary].join(" ").toLocaleLowerCase("es");
  const published=Date.parse((a.published||"")+"T12:00:00Z");
  return (!q||text.includes(q))&&(!onlyKev.checked||a.exploited===true)&&(!showRecent.checked||(Number.isFinite(published)&&published>=cutoff));
 }).sort((a,b)=>rank(b)-rank(a)).slice(0,8);
 if(!matches.length){
  output.innerHTML='<p class="intel-empty">No hay advisories que coincidan con estos filtros en el catálogo disponible. Prueba con otro producto o amplía el periodo.</p>';
  return;
 }
 output.innerHTML=matches.map(a=>{
 const code=esc(a.cve||a.id||"Advisory");
 return '<article class="radar-result"><div class="radar-result-top"><span class="intel-chip '+(a.exploited?'kev':'')+'">'+(a.exploited?'CISA KEV · explotación conocida':'Advisory publicado')+'</span><span class="intel-chip">'+code+'</span></div>'+
 '<h3>'+esc(a.title||a.product||"Advisory de seguridad")+'</h3><p>'+esc(a.product||"Producto por determinar")+' · '+esc(prettyDate(a.published))+'</p>'+
 '<div class="radar-result-bottom"><span>'+esc(a.fixed&&a.fixed!=="Consultar fuente"?"Corrección: "+a.fixed:"Ver corrección en la fuente")+'</span><a href="'+esc(safeUrl(a.url))+'" target="_blank" rel="noopener noreferrer">Consultar fuente ↗</a></div></article>'
 }).join("");
}
async function get(path){
 const response=await fetch(path,{cache:"no-store"});
 if(!response.ok)throw new Error("No disponible: "+path);
 return response.json();
}
Promise.allSettled([get("advisories.json"),get("source-alerts.json"),get("incident-candidates.json")]).then(([a,s,c])=>{
 const errors=[];
 if(a.status==="fulfilled"){
   const data=a.value;advisories=Array.isArray(data.items)?data.items:[];lastAdvisories=data.lastReview||"";
   total.textContent=advisories.length.toLocaleString("es-ES");
   countKev.textContent=advisories.filter(i=>i.exploited).length.toLocaleString("es-ES");
 }else errors.push("catálogo de advisories");
 if(s.status==="fulfilled"){
   const data=s.value;sources=Array.isArray(data.items)?data.items:[];lastSources=data.lastReview||"";
   sourceCount.textContent=Object.values(data.status||{}).filter(v=>v.ok).length+" / "+Object.keys(data.status||{}).length;
 }else errors.push("feeds oficiales");
 if(c.status==="fulfilled"){
   candidates=Array.isArray(c.value.items)?c.value.items:[];
   pending.textContent=candidates.length.toLocaleString("es-ES");
 }else errors.push("cola de revisión");
 const newest=Math.max(Date.parse(lastAdvisories)||0,Date.parse(lastSources)||0);
 const stale=!newest||Date.now()-newest>36*3600000;
 root.classList.toggle("radar-stale",stale);
 const date=newest?new Intl.DateTimeFormat("es-ES",{dateStyle:"medium",timeStyle:"short",timeZone:"Europe/Madrid"}).format(new Date(newest)):"Sin fecha";
 status.textContent=(stale?"Datos atrasados · ":"Última sincronización: ")+date+" · "+(errors.length?"Sin acceso a "+errors.join(", "):"Catálogo y feeds consultados");
 results();
});
search.addEventListener("input",results);
onlyKev.addEventListener("change",results);
showRecent.addEventListener("change",results);
clear.addEventListener("click",()=>{search.value="";onlyKev.checked=false;showRecent.checked=false;results();search.focus()});
})();