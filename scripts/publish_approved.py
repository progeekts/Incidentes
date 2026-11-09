#!/usr/bin/env python3
"""Publica UNA ficha editorial revisada tras una acción manual de un mantenedor.

Entrada: reviewed/<identificador>.json, aprobado y revisado previamente.
No consulta ni interpreta contenido remoto; valida estructura y unicidad.
"""
import datetime as dt
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit

ROOT=Path(__file__).resolve().parent.parent
REVIEWED=ROOT/"reviewed"
INVENTORY=ROOT/"incidents.json"
JS=ROOT/"incidents.js"
RSS=ROOT/"feed.xml"
BASE="https://progeekts.github.io/Incidentes/"
FIELDS=("id","date","title","organization","type","severity","status","incidentState","geo",
        "lead","summary","whyItMatters","affected","actions","sources")
CATEGORIES={"fraude","brecha","vulnerabilidad","malware","otro"}
SEVERITY={"critica","alta","media"}
STATE={"activo","investigacion","seguimiento","contenido","resuelto"}
def fail(msg):raise SystemExit("ERROR: "+msg)
def valid_date(s):
    try:return dt.date.fromisoformat(s)
    except (TypeError,ValueError):fail("Fecha inválida")
def valid_url(s):
    try:
        u=urlsplit(s)
        return u.scheme=="https" and bool(u.hostname) and not u.username and not u.password
    except ValueError:return False
def validate(x, inventory):
    if not isinstance(x,dict):fail("Se requiere un objeto JSON")
    for key in FIELDS:
        if key not in x or x[key] in ("",None,[],{}):fail("Campo obligatorio ausente: "+key)
    if x.get("approved") is not True or not x.get("reviewedBy") or not x.get("reviewedAt"):
        fail("Falta aprobación editorial explícita (approved, reviewedBy, reviewedAt)")
    valid_date(x["date"]);valid_date(x["reviewedAt"])
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{5,100}",x["id"]):fail("ID no permitido")
    if x["type"] not in CATEGORIES or x["severity"] not in SEVERITY or x["incidentState"] not in STATE:
        fail("Categoría, gravedad o estado no permitido")
    if x["status"]!="confirmado":fail("Solo se admiten fichas editorialmente confirmadas")
    if not isinstance(x["actions"],list) or not all(isinstance(v,str) and len(v)>12 for v in x["actions"]):
        fail("Se requieren acciones concretas")
    if not isinstance(x["sources"],list) or not all(isinstance(v,dict) and valid_url(v.get("url","")) and v.get("label") for v in x["sources"]):
        fail("Fuentes HTTPS obligatorias con etiqueta")
    if any(x["id"]==i.get("id") for i in inventory):
        fail("El identificador ya está publicado")
    new_urls={s["url"].rstrip("/") for s in x["sources"]}
    for incident in inventory:
        old_urls={s.get("url","").rstrip("/") for s in incident.get("sources",[])}
        if old_urls & new_urls:
            fail("La fuente ya está asociada a un incidente; revisar posible duplicado")
        if x["title"].strip().casefold()==str(incident.get("title","")).strip().casefold():
            fail("El título ya está publicado")
    if len(x["lead"])<35 or len(x["summary"])<60 or len(x["whyItMatters"])<35:
        fail("Descripción insuficiente para publicación")
def update_rss(records):
    # Fechas de publicación del observatorio, distintas del día original del incidente.
    channel=ET.Element("channel")
    for key,value in (("title","Alertas CiberSec · Incidentes"),("link",BASE),
                      ("description","Incidentes de ciberseguridad documentados con fuentes."),
                      ("language","es")):
        ET.SubElement(channel,key).text=value
    for i in sorted(records,key=lambda r:r.get("publishedDate") or r.get("date",""),reverse=True)[:60]:
        item=ET.SubElement(channel,"item")
        ET.SubElement(item,"title").text=i.get("title")
        ET.SubElement(item,"link").text=BASE+"incidente/?id="+i["id"]
        ET.SubElement(item,"guid",{"isPermaLink":"false"}).text=i["id"]
        ET.SubElement(item,"description").text=i.get("lead") or i.get("summary") or ""
        day=valid_date(i.get("publishedDate") or i.get("date"))
        date=dt.datetime.combine(day,dt.time(12,0,tzinfo=dt.timezone.utc))
        ET.SubElement(item,"pubDate").text=date.strftime("%a, %d %b %Y %H:%M:%S +0000")
    rss=ET.Element("rss",{"version":"2.0"})
    rss.append(channel)
    ET.ElementTree(rss).write(RSS,encoding="utf-8",xml_declaration=True)
def main():
    if len(sys.argv)!=2:fail("Uso: python scripts/publish_approved.py reviewed/<id>.json")
    supplied=sys.argv[1]
    if not re.fullmatch(r"reviewed/[a-z0-9][a-z0-9-]{5,100}\.json",supplied):
        fail("Solo se aceptan rutas reviewed/<id>.json")
    path=(ROOT/supplied).resolve()
    if path.parent!=REVIEWED.resolve() or not path.is_file():fail("Ficha revisada no encontrada")
    incoming=json.loads(path.read_text(encoding="utf-8"))
    inventory=json.loads(INVENTORY.read_text(encoding="utf-8"))
    published=inventory.get("incidents",[])
    validate(incoming,published)
    now=dt.datetime.now(dt.timezone.utc).date().isoformat()
    record={k:v for k,v in incoming.items() if k not in ("approved","reviewedBy","reviewedAt")}
    record["publishedDate"]=now
    record["lastIncidentUpdate"]=record.get("lastIncidentUpdate") or record["date"]
    record["editorialReview"]={"reviewedBy":incoming["reviewedBy"],"reviewedAt":incoming["reviewedAt"]}
    record.setdefault("timeline",[{"date":record["date"],"text":"Fecha original del incidente según las fuentes."},
                                 {"date":now,"text":"Ficha revisada e incorporada al observatorio."}])
    new_records=[record]+published
    raw=JS.read_text(encoding="utf-8")
    match=re.match(r"^window\.INCIDENTS=(\[[\s\S]*?\]);\s*window\.INCIDENT_META=([\s\S]*?);\s*$",raw)
    if not match:fail("No se puede interpretar incidents.js")
    js_list=json.loads(match.group(1))
    if {i.get("id") for i in js_list}!={i.get("id") for i in published}:fail("Los dos inventarios no coinciden")
    meta=json.loads(match.group(2))
    meta["lastUpdated"]=now
    inventory["incidents"]=new_records
    inventory["updated"]=now
    # Escrituras después de terminar la validación.
    INVENTORY.write_text(json.dumps(inventory,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    JS.write_text("window.INCIDENTS="+json.dumps([record]+js_list,ensure_ascii=False,indent=2)+";\nwindow.INCIDENT_META="+json.dumps(meta,ensure_ascii=False)+";\n",encoding="utf-8")
    update_rss(new_records)
    print("Ficha editorial publicada:",record["id"])
if __name__=="__main__":
    main()
