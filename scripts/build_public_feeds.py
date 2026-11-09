#!/usr/bin/env python3
"""Construye RSS diferenciados para vulnerabilidades y brechas editoriales."""
import datetime as dt
import email.utils
import json
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
BASE="https://progeekts.github.io/Incidentes/"
ET.register_namespace("atom","http://www.w3.org/2005/Atom")

def date_rfc(value):
    try:
        parsed=dt.date.fromisoformat(str(value)[:10])
    except ValueError:
        return None
    stamp=dt.datetime.combine(parsed,dt.time(12,0,tzinfo=dt.timezone.utc))
    return email.utils.format_datetime(stamp)

def write_feed(name,title,description,site,entries):
    rss=ET.Element("rss",{"version":"2.0"})
    channel=ET.SubElement(rss,"channel")
    for key,value in [("title",title),("link",site),("description",description),("language","es")]:
        ET.SubElement(channel,key).text=value
    ET.SubElement(channel,"lastBuildDate").text=email.utils.format_datetime(dt.datetime.now(dt.timezone.utc))
    ET.SubElement(channel,"{http://www.w3.org/2005/Atom}link",{"href":BASE+name,"rel":"self","type":"application/rss+xml"})
    for row in entries[:80]:
        item=ET.SubElement(channel,"item")
        ET.SubElement(item,"title").text=row["title"]
        ET.SubElement(item,"link").text=row["link"]
        ET.SubElement(item,"guid",{"isPermaLink":"false"}).text=row["id"]
        ET.SubElement(item,"description").text=row["description"]
        if row.get("pubDate"):
            ET.SubElement(item,"pubDate").text=row["pubDate"]
    ET.ElementTree(rss).write(ROOT/name,encoding="utf-8",xml_declaration=True)
    print(name,":",min(80,len(entries)),"entradas")

def main():
    adv=json.loads((ROOT/"advisories.json").read_text(encoding="utf-8"))
    entries=[]
    for a in adv.get("items",[]):
        url=a.get("url","")
        if not url.startswith("https://") or not a.get("id"):
            continue
        evidence="Catalogado en CISA KEV. " if a.get("exploited") else ""
        entries.append({
            "id":a["id"],
            "title":f"{a.get('cve') or a['id']} · {a.get('title') or a.get('product') or 'Advisory'}",
            "link":url,
            "description":evidence+(a.get("summary") or "")[:450]+" | Producto: "+(a.get("product") or "No indicado")+" | Corrección: "+(a.get("fixed") or "Consultar fuente"),
            "pubDate":date_rfc(a.get("published"))
        })
    entries.sort(key=lambda x:x.get("pubDate") or "",reverse=True)
    # La fecha RFC es útil para lectores pero no para ordenar: el catálogo original
    # sí conserva YYYY-MM-DD; ordenar allí primero.
    order={a["id"]:a.get("published") or "" for a in adv.get("items",[]) if a.get("id")}
    entries.sort(key=lambda x:order.get(x["id"],""),reverse=True)
    write_feed("advisories-feed.xml","Alertas CiberSec · Security Advisories",
               "Vulnerabilidades y avisos de seguridad publicados en fuentes externas; no equivalen a ataques confirmados.",
               BASE+"advisories.html",entries)

    records=json.loads((ROOT/"incidents.json").read_text(encoding="utf-8")).get("incidents",[])
    breaches=[]
    for i in records:
        if i.get("type")!="brecha" or i.get("status")!="confirmado" or not i.get("id"):
            continue
        breaches.append({
            "id":i["id"],"title":i.get("title") or i["id"],
            "link":BASE+"incidente/?id="+i["id"],
            "description":(i.get("lead") or i.get("summary") or "")[:500],
            "pubDate":date_rfc(i.get("publishedDate") or i.get("date")),
            "date":i.get("publishedDate") or i.get("date") or ""
        })
    breaches.sort(key=lambda x:x["date"],reverse=True)
    write_feed("brechas-feed.xml","Alertas CiberSec · Brechas documentadas",
               "Fichas editoriales sobre accesos no autorizados y posibles exposiciones; no implica exfiltración confirmada en todos los casos.",
               BASE+"brechas.html",breaches)

if __name__=="__main__":
    main()
