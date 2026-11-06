(() => {
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const safeUrl=s=>{try{const u=new URL(s);return u.protocol==="https:"?u.href:"#"}catch{return "#"}};
const sev={critical:"Crítica",high:"Alta",moderate:"Media",medium:"Media",low:"Baja",unknown:"Sin clasificar"};
const date=d=>{if(!d)return "Sin fecha";const x=new Date(d.length===10?d+"T12:00:00Z":d);return Number.isNaN(x.getTime())?d:new Intl.DateTimeFormat("es-ES",{day:"numeric",month:"short",year:"numeric",timeZone:"Europe/Madrid"}).format(x)};
let rows=[],page=24;
const card=a=>'<article class="intel-card"><header>'+
'<span class="intel-chip '+esc(a.severity)+'">'+esc(sev[a.severity]||a.severity||"Sin clasificar")+'</span>'+
(a.exploited?'<span class="intel-chip kev">CISA KEV · explotación conocida</span>':'')+
'<span class="intel-chip">'+esc(a.cve||a.id||"Advisory")+'</span></header>'+
'<h3>'+esc(a.title)+'</h3><p class="detail"><b>Producto:</b> '+esc(a.product||"No especificado")+'</p>'+
'<p class="desc">'+esc(a.summary||"Consultar el advisory original para conocer los detalles.")+'</p>'+
'<p class="detail"><b>Versiones afectadas:</b> '+esc(a.affected||"Consultar fabricante")+'</p>'+
'<p class="detail"><b>Corrección:</b> '+esc(a.fixed||"Consultar fabricante")+'</p>'+
'<div class="foot"><span>'+esc(date(a.published))+' · '+esc(a.source)+'</span><a href="'+esc(safeUrl(a.url))+'" target="_blank" rel="noopener noreferrer">Ver advisory ↗</a></div></article>';
function render(){
 const query=$("aSearch").value.trim().toLocaleLowerCase("es");
 const severity=$("aSeverity").value, exploit=$("aExploitation").value,eco=$("aEcosystem").value;
 const filtered=rows.filter(a=>(severity==="all"||a.severity===severity||severity==="moderate"&&a.severity==="medium")&&(exploit!=="kev"||a.exploited)&&(eco==="all"||a.ecosystem===eco)&&(!query||[a.id,a.cve,a.title,a.product,a.ecosystem,a.summary].join(" ").toLocaleLowerCase("es").includes(query)));
 $("aCount").textContent=filtered.length+" advisories coinciden con los filtros";
 $("advisoryList").innerHTML=filtered.length?filtered.slice(0,page).map(card).join(""):'<p class="intel-empty">No hay advisories con estos filtros.</p>';
 $("aMore").hidden=filtered.length<=page;
}
fetch("advisories.json",{cache:"no-store"}).then(r=>{if(!r.ok)throw Error("Archivo no disponible");return r.json()}).then(data=>{
 rows=Array.isArray(data.items)?data.items:[];
 rows.sort((a,b)=>(b.published||"").localeCompare(a.published||"")||(a.id||"").localeCompare(b.id||""));
 $("aTotal").textContent=rows.length;
 $("aCritical").textContent=rows.filter(a=>a.severity==="critical").length;
 $("aExploited").textContent=rows.filter(a=>a.exploited).length;
 $("aReview").textContent=date(data.lastReview);
 $("highlights").innerHTML=rows.filter(a=>a.highlight).map(card).join("")||'<p class="intel-empty">No hay destacados disponibles.</p>';
 const ecosystems=[...new Set(rows.map(a=>a.ecosystem).filter(Boolean))].sort().slice(0,100);
 $("aEcosystem").innerHTML='<option value="all">Todos los ecosistemas</option>'+ecosystems.map(e=>'<option value="'+esc(e)+'">'+esc(e)+'</option>').join("");
 $("aStatus").textContent=Object.entries(data.sourceStatus||{}).map(([k,v])=>k+": "+(v&&typeof v==="object"?(v.ok?"correcto":"sin respuesta"):v)).join(" · ")||"Fuentes aún no sincronizadas";
 ["aSearch","aSeverity","aExploitation","aEcosystem"].forEach(id=>$(id).addEventListener("input",()=>{page=24;render()}));
 $("aMore").addEventListener("click",()=>{page+=24;render()});
 render();
}).catch(()=>{$("advisoryList").innerHTML='<p class="intel-empty">No se puede cargar el catálogo en este momento.</p>'; $("aStatus").textContent="Sin datos de sincronización."});
})();