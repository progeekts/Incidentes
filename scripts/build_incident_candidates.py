#!/usr/bin/env python3
"""Clasifica avisos como CANDIDATOS, sin publicarlos como incidentes confirmados."""
import datetime as dt
import email.utils
import hashlib
import json
import re
import unicodedata
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT=Path(__file__).resolve().parent.parent
INPUT=ROOT/"source-alerts.json"
INCIDENTS=ROOT/"incidents.json"
OUTPUT=ROOT/"incident-candidates.json"
MAX_AGE_DAYS=60
MAX_CANDIDATES=100
KEYWORDS={
 "brecha":("data breach","data leak","data exposure","exfiltrat","brecha de datos","filtracion de datos","fuga de datos","robo de datos","datos personales","personal data","ransomware","unauthorized access"),
 "fraude":("phishing","smishing","fraude","suplant","estafa","scam"),
 "vulnerabilidad":("vulnerab","cve-","security advisory","critical flaw","patch","rce","remote code execution"),
 "malware":("malware","troyano","ransomware","infostealer","spyware","backdoor")
}
def normalize(value):
    value=unicodedata.normalize("NFKD",str(value or "")).encode("ascii","ignore").decode().lower()
    return re.sub(r"\s+"," ",re.sub(r"[^a-z0-9 ]"," ",value)).strip()
def parse_date(value):
    if not value:return None
    try:
        return email.utils.parsedate_to_datetime(value).astimezone(dt.timezone.utc)
    except (ValueError,TypeError,IndexError):
        try:return dt.datetime.fromisoformat(value.replace("Z","+00:00")).astimezone(dt.timezone.utc)
        except (ValueError,TypeError):return None
def classification(item):
    text=normalize((item.get("title") or "")+" "+(item.get("summary") or "")[:180])
    scores={key:sum(bool(needle in text) for needle in words) for key,words in KEYWORDS.items()}
    result=sorted(scores,key=lambda k:(-scores[k],list(KEYWORDS).index(k)))
    return result[0] if scores[result[0]] else "otro"
def main():
    payload=json.loads(INPUT.read_text("utf-8"))
    incidents=json.loads(INCIDENTS.read_text("utf-8")).get("incidents",[])
    existing_urls={x.get("url","").rstrip("/") for i in incidents for x in i.get("sources",[])}
    existing_titles={normalize(i.get("title")) for i in incidents}
    existing_cves={v.upper() for i in incidents for v in re.findall(r"CVE-\d{4}-\d{4,}",json.dumps(i))}
    now=dt.datetime.now(ZoneInfo("Europe/Madrid"))
    previous={}
    if OUTPUT.exists():
        try:previous={i["id"]:i for i in json.loads(OUTPUT.read_text("utf-8")).get("items",[])}
        except (KeyError,ValueError,TypeError):pass
    candidates={}
    for item in payload.get("items",[]):
        url=item.get("url","").rstrip("/")
        title=(item.get("title") or "").strip()
        date=parse_date(item.get("published"))
        if not url.startswith("https://") or not title or not date:
            continue
        days=(now.astimezone(dt.timezone.utc)-date).total_seconds()/86400
        if days < -1 or days > MAX_AGE_DAYS:
            continue
        title_key=normalize(title)
        if url in existing_urls or title_key in existing_titles:
            continue
        cves={v.upper() for v in re.findall(r"CVE-\d{4}-\d{4,}",title)}
        if cves and cves.issubset(existing_cves):
            continue
        iid=hashlib.sha256(url.encode()).hexdigest()[:20]
        old=previous.get(iid,{})
        category=classification(item)
        candidates[iid]={
            "id":iid,"title":title[:280],"source":item.get("source",""),
            "sourceUrl":url,"published":date.date().isoformat(),
            "categoryHint":category,"summary":(item.get("summary") or "")[:350],
            "status":"pendiente", "verification":"No verificado individualmente",
            "firstSeen":old.get("firstSeen",now.isoformat(timespec="seconds")),
            "lastSeen":now.isoformat(timespec="seconds")
        }
    ordered=sorted(candidates.values(),key=lambda c:(c["published"],c["id"]),reverse=True)[:MAX_CANDIDATES]
    data={"lastGenerated":now.isoformat(timespec="seconds"),
          "sourceReview":payload.get("lastReview"),"count":len(ordered),
          "disclaimer":"Candidatos encontrados en fuentes externas. No son incidentes confirmados ni exfiltraciones demostradas.",
          "items":ordered}
    OUTPUT.write_text(json.dumps(data,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("Candidatos a revisión:",len(ordered),"por tipo:",{k:sum(x["categoryHint"]==k for x in ordered) for k in KEYWORDS})
if __name__=="__main__":
    main()
