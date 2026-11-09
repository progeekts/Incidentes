#!/usr/bin/env python3
"""Recopila avisos oficiales. No convierte avisos en incidentes verificados."""
import datetime as dt
import email.utils
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.request
import xml.etree.ElementTree as ET
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "source-alerts.json"
SOURCES = [
    ("INCIBE Ciudadanía", "https://www.incibe.es/ciudadania/avisos/feed"),
    ("INCIBE-CERT", "https://www.incibe.es/incibe-cert/alerta-temprana/avisos-sci/feed"),
    ("CERT-EU", "https://cert.europa.eu/publications/security-advisories-rss"),
    ("CISA", "https://www.cisa.gov/cybersecurity-advisories/alerts.xml"),
]
def clean(value):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]*>", " ", value or "")).strip()

def child_text(el, names):
    for name in names:
        value = el.findtext(name)
        if value:
            return clean(value)
    return ""

def parse(xml, source):
    root = ET.fromstring(xml)
    entries = root.findall(".//item")
    if not entries:
        ns = "{http://www.w3.org/2005/Atom}"
        entries = root.findall(".//" + ns + "entry")
    results = []
    for entry in entries[:35]:
        title = child_text(entry, ["title", "{http://www.w3.org/2005/Atom}title"])
        url = child_text(entry, ["link", "guid", "{http://www.w3.org/2005/Atom}id"])
        atom_link = entry.find("{http://www.w3.org/2005/Atom}link")
        if atom_link is not None and atom_link.attrib.get("href"):
            url = atom_link.attrib["href"]
        description = child_text(entry, ["description", "{http://www.w3.org/2005/Atom}summary"])
        date = child_text(entry, ["pubDate", "{http://www.w3.org/2005/Atom}updated", "{http://www.w3.org/2005/Atom}published"])
        if not title or not url.startswith("https://"):
            continue
        results.append({"id": hashlib.sha256(url.encode()).hexdigest()[:20], "source":source, "title":title[:280], "url":url, "published":date[:100], "summary":description[:450]})
    return results

def main():
    madrid = dt.datetime.now(ZoneInfo("Europe/Madrid"))
    old = {}
    if OUTPUT.exists():
        try:
            old = json.loads(OUTPUT.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            pass
    previous = {e["id"]:e for e in old.get("items",[]) if "id" in e}
    items = {}
    status = {}
    for source, url in SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent":"AlertasCiberSec/1.0 (public RSS aggregation)", "Accept":"application/rss+xml, application/atom+xml, application/xml"})
            with urllib.request.urlopen(req,timeout=22) as response:
                payload = response.read(2_500_000)
            parsed = parse(payload, source)
            if not parsed:
                raise ValueError("Feed sin entradas utilizables")
            for item in parsed:
                items[item["id"]] = item
            status[source] = {"ok":True, "count":len(parsed)}
        except Exception as exc:
            status[source] = {"ok":False, "error":str(exc)[:180]}
            for item in previous.values():
                if item.get("source") == source:
                    items[item["id"]] = item
    if not any(v["ok"] for v in status.values()):
        raise RuntimeError("Ninguna fuente respondió correctamente; no se sobrescriben datos.")
    now = madrid.isoformat(timespec="seconds")
    data = {"lastReview":now, "timezone":"Europe/Madrid", "status":status, "disclaimer":"Avisos recopilados automáticamente de fuentes externas, sin validación editorial individual. No equivalen a incidentes confirmados por Alertas CiberSec.", "items":list(items.values())[:160]}
    serialized = json.dumps(data,ensure_ascii=False,indent=2)+"\n"
    if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != serialized:
        OUTPUT.write_text(serialized,encoding="utf-8")
    print(json.dumps({"lastReview":now,"sources":status,"items":len(data["items"])},ensure_ascii=False))

if __name__=="__main__":
    main()
