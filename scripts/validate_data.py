#!/usr/bin/env python3
"""Valida integridad básica antes de publicar los datos del observatorio."""
import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

ROOT=Path(__file__).resolve().parent.parent
ERRORS=[]

def load(name):
    try:
        data=json.loads((ROOT/name).read_text(encoding="utf-8"))
        if not isinstance(data,dict):raise ValueError("objeto raíz requerido")
        return data
    except (OSError,ValueError) as exc:
        ERRORS.append(f"{name}: {exc}")
        return {}

def unique(name,items,key):
    seen=set()
    for index,item in enumerate(items):
        if not isinstance(item,dict):
            ERRORS.append(f"{name}: elemento #{index} no es objeto")
            continue
        value=item.get(key)
        if not isinstance(value,str) or not value:
            ERRORS.append(f"{name}: elemento #{index} sin {key}")
        elif value in seen:
            ERRORS.append(f"{name}: identificador duplicado {value}")
        seen.add(value)

def timestamp(name,value):
    try:
        dt=datetime.fromisoformat(value.replace("Z","+00:00"))
        if dt.tzinfo is None:raise ValueError("falta zona horaria")
    except (AttributeError,ValueError) as exc:ERRORS.append(f"{name}: marca temporal inválida ({exc})")

def urls(name,items,keys):
    for item in items:
        if not isinstance(item,dict):continue
        for key in keys:
            url=item.get(key)
            if not url:continue
            parts=urlsplit(url)
            if parts.scheme!="https" or not parts.hostname:
                ERRORS.append(f"{name}: URL no HTTPS ({key}) {str(url)[:120]}")
                if len(ERRORS)>30:return

def main():
    inc=load("incidents.json")
    editorial=inc.get("incidents",[])
    if not isinstance(editorial,list):ERRORS.append("incidents.json: incidents no es lista");editorial=[]
    unique("incidents.json",editorial,"id")
    # JS usado por la portada y el inventario JSON han de contener los mismos registros.
    try:
        js=(ROOT/"incidents.js").read_text(encoding="utf-8")
        match=re.search(r"^window\.INCIDENTS=(\[.*?\]);\s*window\.INCIDENT_META=",js,re.DOTALL)
        if not match:raise ValueError("No se encuentra window.INCIDENTS")
        js_entries=json.loads(match.group(1))
        json_ids={i.get("id") for i in editorial}
        js_ids={i.get("id") for i in js_entries}
        if len(js_entries)!=len(editorial) or json_ids!=js_ids:
            ERRORS.append("El inventario editorial JSON no coincide con incidents.js")
    except (OSError,ValueError) as exc:
        ERRORS.append(f"incidents.js: {exc}")

    sources=load("source-alerts.json")
    feeds=sources.get("items",[])
    unique("source-alerts.json",feeds,"id")
    timestamp("source-alerts.json.lastReview",sources.get("lastReview"))
    urls("source-alerts.json",feeds,["url"])

    advisories=load("advisories.json")
    rows=advisories.get("items",[])
    unique("advisories.json",rows,"id")
    timestamp("advisories.json.lastReview",advisories.get("lastReview"))
    urls("advisories.json",rows,["url"])

    candidates=load("incident-candidates.json")
    queue=candidates.get("items",[])
    unique("incident-candidates.json",queue,"id")
    timestamp("incident-candidates.json.lastGenerated",candidates.get("lastGenerated"))
    urls("incident-candidates.json",queue,["sourceUrl"])
    if candidates.get("count")!=len(queue):
        ERRORS.append("incident-candidates.json: count no coincide con la lista")
    if any(item.get("status")!="pendiente" for item in queue if isinstance(item,dict)):
        ERRORS.append("incident-candidates.json: estados no permitidos")

    if ERRORS:
        for error in ERRORS[:30]:print("ERROR:",error)
        raise SystemExit(1)
    print(f"OK: {len(editorial)} fichas editoriales, {len(feeds)} avisos, {len(rows)} advisories, {len(queue)} candidatos. Datos íntegros.")

if __name__=="__main__":
    main()
