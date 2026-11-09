#!/usr/bin/env python3
"""Preevaluación de avisos para revisión humana, sin publicación editorial.

Reglas conservadoras:
- Detecta pistas, no confirma una brecha ni un ataque.
- Descarta enlaces ya presentes y nombres/CVE idénticos.
- Solo da paso a fichas publicadas tras aprobación editorial externa.
"""
import datetime as dt
import json
import re
import unicodedata
from pathlib import Path
from zoneinfo import ZoneInfo
from urllib.parse import urlsplit

ROOT=Path(__file__).resolve().parent.parent
CANDIDATES=ROOT/"incident-candidates.json"
INCIDENTS=ROOT/"incidents.json"
OUTPUT=ROOT/"incident-review-queue.json"
MAX_ITEMS=80
OFFICIAL_SOURCES={"CISA","CERT-EU","INCIBE-CERT","INCIBE Ciudadanía"}
DATA_TERMS=("data breach","brecha de datos","data stolen","data leak","exfiltrat","datos filtrados","robo de datos")
INCIDENT_TERMS=("incident","incidente","ransomware","breach","compromise","intrusion","intrusión","unauthorized access","acceso no autorizado")
GENERIC_TERMS=("weekly roundup","newsletter","weekly digest","summary","security tips","how to","consejos")
def norm(s):
    raw=unicodedata.normalize("NFKD",str(s or "")).encode("ascii","ignore").decode().lower()
    return re.sub(r"\s+"," ",raw).strip()
def cves(text):
    return set(re.findall(r"CVE-\d{4}-\d{4,}",str(text or ""),re.IGNORECASE))
def main():
    payload=json.loads(CANDIDATES.read_text(encoding="utf-8"))
    incidents=json.loads(INCIDENTS.read_text(encoding="utf-8")).get("incidents",[])
    prior_urls={x.get("url","").rstrip("/") for i in incidents for x in i.get("sources",[])}
    prior_titles={norm(i.get("title")) for i in incidents}
    prior_cves=set().union(*(cves(json.dumps(i)) for i in incidents)) if incidents else set()
    now=dt.datetime.now(ZoneInfo("Europe/Madrid")).isoformat(timespec="seconds")
    items=[]
    for candidate in payload.get("items",[]):
        url=candidate.get("sourceUrl","")
        if urlsplit(url).scheme!="https" or not candidate.get("title"):
            continue
        title=candidate["title"]
        text=norm(title+" "+candidate.get("summary","")[:200])
        extracted=cves(title)
        duplicate_url=url.rstrip("/") in prior_urls
        duplicate_title=norm(title) in prior_titles
        duplicate_cve=bool(extracted) and extracted.issubset(prior_cves)
        if duplicate_url or duplicate_title or duplicate_cve:
            continue
        src=candidate.get("source","")
        category=candidate.get("categoryHint","otro")
        official=src in OFFICIAL_SOURCES
        source_type="official" if official else "other"
        is_generic=any(x in text for x in GENERIC_TERMS)
        has_incident_word=any(x in text for x in INCIDENT_TERMS)
        has_data_word=any(x in text for x in DATA_TERMS)
        score=min(100,(35 if official else 10)+(25 if category=="brecha" else 17 if category=="malware" else 13 if category=="fraude" else 8)+(17 if has_incident_word else 0)+(10 if has_data_word else 0)+(6 if extracted else 0)-(24 if is_generic else 0))
        # Una fuente oficial no convierte automáticamente una alerta genérica en brecha de datos.
        reason=("Puede describir una exposición, requiere confirmar empresa, datos y alcance." if category=="brecha" else
                "Puede describir una vulnerabilidad; normalmente debe permanecer en Security Advisories." if category=="vulnerabilidad" else
                "Revisar el aviso y comprobar que describe un caso concreto, no una guía general.")
        status="pendiente de verificación humana"
        items.append({"id":candidate["id"],"title":title[:280],"source":src,"sourceType":source_type,"sourceUrl":url,"published":candidate.get("published",""),"categoryHint":category,"score":max(0,score),"reason":reason,"status":status,"evidenceCount":1,
                      "duplicateCheck":"sin coincidencia exacta por URL, título o CVE; no descarta duplicados semánticos",
                      "requires":["Confirmar hecho y fecha con fuente primaria","Identificar organización y alcance real","Distinguir acceso, exposición y exfiltración","Añadir recomendaciones comprobables","Aprobar ficha editorial antes de publicar"]})
    items.sort(key=lambda x:(-x["score"],x["published"],x["id"]))
    data={"lastGenerated":now,"sourceReview":payload.get("sourceReview"),"count":min(len(items),MAX_ITEMS),
          "publicationPolicy":"Solo cola de revisión. Prohibida la incorporación automática a incidents.json, incidents.js o RSS editorial.",
          "items":items[:MAX_ITEMS]}
    OUTPUT.write_text(json.dumps(data,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"reviewItems":data["count"],"publicationAutomatic":False},ensure_ascii=False))
if __name__=="__main__":
    main()
