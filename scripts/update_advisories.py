#!/usr/bin/env python3
"""Sincroniza advisories públicos de GitHub y CISA KEV con presupuesto limitado.

No modifica incidentes ni da por confirmadas exfiltraciones. Los advisories
importados conservan referencias y descripciones originales.
"""
import datetime as dt
import json
import os
import urllib.request
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT=Path(__file__).resolve().parent.parent
TARGET=ROOT/"advisories.json"
GH_URL="https://api.github.com/advisories?type=reviewed&per_page=100&sort=published&direction=desc&page="
KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_KEEP=1200

def fetch(url,timeout=20):
    headers={"User-Agent":"AlertasCiberSec/1.0 (public advisory aggregator)", "Accept":"application/vnd.github+json" if "api.github.com" in url else "application/json"}
    token=os.environ.get("GH_ADVISORY_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token and "api.github.com" in url:
        headers["Authorization"]="Bearer "+token
    with urllib.request.urlopen(urllib.request.Request(url,headers=headers),timeout=timeout) as response:
        return json.loads(response.read(3_000_000).decode("utf-8"))

def short(value,n=450):
    return str(value or "").replace("\r"," ").replace("\n"," ").strip()[:n]

def convert(gh):
    if gh.get("withdrawn_at") or not gh.get("ghsa_id"):
        return None
    vulns=gh.get("vulnerabilities") or []
    packages=[v.get("package") or {} for v in vulns if isinstance(v,dict)]
    pkg_names=sorted({p.get("name","") for p in packages if p.get("name")})
    ecosystems=sorted({p.get("ecosystem","") for p in packages if p.get("ecosystem")})
    patched=sorted({v.get("first_patched_version","") for v in vulns if isinstance(v,dict) and v.get("first_patched_version")})
    affected=sorted({v.get("vulnerable_version_range","") for v in vulns if isinstance(v,dict) and v.get("vulnerable_version_range")})
    scores=gh.get("cvss_severities") or {}
    cvss=(scores.get("cvss_v4") or {}).get("score") or (scores.get("cvss_v3") or {}).get("score")
    cve=gh.get("cve_id")
    return {
      "id":gh["ghsa_id"],"cve":cve or "","title":short(gh.get("summary"),200),
      "product":", ".join(pkg_names[:3]) or "Software sin paquete identificado",
      "ecosystem":", ".join(ecosystems) or "General",
      "severity":gh.get("severity") or "unknown","cvss":cvss,
      "published":(gh.get("published_at") or "")[:10],
      "fixed":", ".join(patched[:5]) or "Consultar fuente",
      "affected":", ".join(affected[:5]) or "Consultar fuente",
      "summary":short(gh.get("description") or gh.get("summary"),550),
      "exploited":False,"exploitationStatus":"No confirmado por este catálogo",
      "url":gh.get("html_url") or "https://github.com/advisories/"+gh["ghsa_id"],
      "source":"GitHub Advisory Database", "highlight":False
    }

def main():
    old=json.loads(TARGET.read_text("utf-8")) if TARGET.exists() else {}
    items={i["id"]:i for i in old.get("items",[]) if i.get("id")}
    status={}
    github_success=False
    collected=[]
    # 300 avisos por pasada, conservando histórico hasta 1200.
    for page in range(1,4):
        try:
            arr=fetch(GH_URL+str(page))
            if not isinstance(arr,list):
                raise ValueError("respuesta inesperada")
            collected.extend(arr)
            github_success=True
            if len(arr)<100:
                break
        except Exception as exc:
            status["GitHub Advisory Database"]={"ok":False,"error":short(exc,160),"pagesFetched":page-1}
            break
    if github_success:
        for advisory in collected:
            i=convert(advisory)
            if i:
                # Conservar las fichas destacadas redactadas desde comunicados oficiales.
                old_item=items.get(i["id"],{})
                items[i["id"]]={**i,**({"highlight":True} if old_item.get("highlight") else {})}
        status.setdefault("GitHub Advisory Database",{"ok":True,"count":len(collected)})
    kev_set=set()
    try:
        kev=fetch(KEV_URL)
        kev_set={v.get("cveID","") for v in kev.get("vulnerabilities",[])}
        status["CISA KEV"]={"ok":True,"count":len(kev_set)}
    except Exception as exc:
        status["CISA KEV"]={"ok":False,"error":short(exc,160)}
    for i in items.values():
        if i.get("cve") in kev_set:
            i["exploited"]=True
            i["exploitationStatus"]="Incluida en CISA KEV"
        elif status.get("CISA KEV",{}).get("ok"):
            # El hecho de no figurar en KEV no demuestra que no esté explotada.
            if i.get("exploitationStatus")=="Incluida en CISA KEV":
                i["exploitationStatus"]="Sin confirmar en catálogo KEV actual"
            i["exploited"]=False
    if not any(x.get("ok") for x in status.values()):
        raise RuntimeError("No respondió ninguna fuente: conservar el último fichero.")
    ordered=sorted(items.values(),key=lambda x:(bool(x.get("highlight")),x.get("published") or "",x.get("id") or ""),reverse=True)
    data={"lastReview":dt.datetime.now(ZoneInfo("Europe/Madrid")).isoformat(timespec="seconds"),
          "sourceStatus":status,
          "note":"Catálogo parcial y acumulativo: 300 advisories por consulta (máximo histórico local 1200). La ausencia en CISA KEV no implica ausencia de explotación.",
          "items":ordered[:MAX_KEEP]}
    TARGET.write_text(json.dumps(data,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"count":len(data["items"]),"sources":status},ensure_ascii=False))
if __name__=="__main__":
    main()
