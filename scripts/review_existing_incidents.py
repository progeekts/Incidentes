#!/usr/bin/env python3
"""Seguimiento acotado de fuentes vinculadas a incidentes publicados.

No modifica fichas editoriales, estados ni recomendaciones: un cambio remoto
solo crea una señal PENDIENTE de comprobación humana.
"""
import datetime as dt
import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "incidents.json"
OUTPUT = ROOT / "incident-review-state.json"
MAX_INCIDENTS = 10
MAX_SOURCES_PER_INCIDENT = 2
MAX_ELAPSED_SECONDS = 225
SOURCE_TIMEOUT = 9
BODY_LIMIT = 150_000
NOW = dt.datetime.now(ZoneInfo("Europe/Madrid"))
NOW_UTC = NOW.astimezone(dt.timezone.utc)
START = time.monotonic()
INTERVALS = {"activo": 1, "investigacion": 3, "seguimiento": 7, "contenido": 7, "resuelto": 30}
USER_AGENT = "AlertasCiberSec/1.0 (source monitoring; contact: GitHub progeekts/Incidentes)"


def read_json(path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def parse_date(value):
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(dt.timezone.utc)
    except (ValueError, AttributeError):
        return None


def cadence(incident):
    state = incident.get("incidentState", "")
    if state == "activo" or incident.get("severity") == "critica" and state not in ("resuelto", "contenido"):
        return 1
    return INTERVALS.get(state, 30)


def safe_url(url):
    # Solo fuentes HTTPS públicas, sin credenciales, localhost ni direcciones IP literales.
    from urllib.parse import urlsplit
    from ipaddress import ip_address
    if not isinstance(url, str) or len(url) > 2048:
        return False
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.port not in (None, 443):
        return False
    host = parts.hostname.lower()
    if host in ("localhost",) or host.endswith((".local", ".internal", ".localhost")):
        return False
    try:
        ip_address(host)
        return False
    except ValueError:
        return "." in host


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # No seguir redirecciones hacia direcciones no examinadas.
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def inspect_source(url, previous):
    if not safe_url(url):
        return {"ok": False, "reason": "URL fuera de la política HTTPS", "url": url}
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html, application/xml, text/plain, application/json"}
    if previous.get("etag"):
        headers["If-None-Match"] = previous["etag"]
    if previous.get("lastModified"):
        headers["If-Modified-Since"] = previous["lastModified"]
    request = urllib.request.Request(url, headers=headers)
    try:
        response = OPENER.open(request, timeout=SOURCE_TIMEOUT)
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return {**previous, "url": url, "ok": True, "changed": False, "httpStatus": 304}
        return {**previous, "url": url, "ok": False, "reason": "HTTP " + str(exc.code)}
    except (OSError, ValueError) as exc:
        return {**previous, "url": url, "ok": False, "reason": str(exc)[:120]}
    try:
        with response:
            mime = response.headers.get_content_type()
            if mime not in ("text/html", "text/plain", "application/json", "application/xml", "text/xml", "application/xhtml+xml"):
                return {**previous, "url": url, "ok": False, "reason": "Formato no comparable: " + mime}
            body = response.read(BODY_LIMIT + 1)
            if len(body) > BODY_LIMIT:
                return {**previous, "url": url, "ok": False, "reason": "Contenido demasiado grande para comparación"}
            # Comparación orientativa: un cambio HTML no demuestra una evolución del incidente.
            digest = hashlib.sha256(body).hexdigest()
            old_digest = previous.get("sha256")
            return {"url": url, "ok": True, "httpStatus": response.status,
                    "sha256": digest, "etag": response.headers.get("ETag", "")[:180],
                    "lastModified": response.headers.get("Last-Modified", "")[:100],
                    "changed": bool(old_digest and old_digest != digest),
                    "baseline": not bool(old_digest)}
    except (OSError, ValueError) as exc:
        return {**previous, "url": url, "ok": False, "reason": str(exc)[:120]}


def main():
    incidents = read_json(INVENTORY, {}).get("incidents", [])
    state = read_json(OUTPUT, {"version": 1, "incidents": {}})
    records = state.setdefault("incidents", {})
    due = []
    for incident in incidents:
        iid = incident.get("id")
        if not iid:
            continue
        record = records.get(iid, {})
        days = cadence(incident)
        last = parse_date(record.get("lastChecked", ""))
        next_due = last + dt.timedelta(days=days) if last else NOW_UTC
        if next_due <= NOW_UTC:
            priority = (0 if incident.get("incidentState") == "activo" else
                        1 if incident.get("severity") == "critica" else
                        2 if incident.get("incidentState") == "investigacion" else
                        3 if incident.get("incidentState") == "seguimiento" else 4)
            due.append((priority, next_due, incident))
    due.sort(key=lambda row: (row[0], row[1], row[2].get("id", "")))
    checked = 0
    for _, _, incident in due[:MAX_INCIDENTS]:
        if time.monotonic() - START > MAX_ELAPSED_SECONDS:
            break
        iid = incident["id"]
        record = records.get(iid, {})
        previous_sources = {s.get("url"): s for s in record.get("sources", [])}
        sources = []
        for entry in incident.get("sources", [])[:MAX_SOURCES_PER_INCIDENT]:
            url = entry.get("url", "")
            if not url:
                continue
            if time.monotonic() - START > MAX_ELAPSED_SECONDS:
                break
            sources.append(inspect_source(url, previous_sources.get(url, {})))
        successes = sum(s.get("ok", False) for s in sources)
        # No se considera revisado con éxito un incidente cuyos enlaces han fallado.
        success = bool(sources and successes == len(sources))
        changes = [s["url"] for s in sources if s.get("changed")]
        baseline = not record.get("lastChecked")
        old_flags = set(record.get("pendingEvidence", []))
        old_flags.update(changes)
        if success:
            next_check = NOW + dt.timedelta(days=cadence(incident))
        else:
            next_check = NOW + dt.timedelta(days=1)
        records[iid] = {
            "lastChecked": NOW.isoformat(timespec="seconds"),
            "nextCheck": next_check.isoformat(timespec="seconds"),
            "checkResult": "checked" if success else "partial_or_failed",
            "editorialReview": "pending" if old_flags else "not_requested",
            "pendingEvidence": sorted(old_flags)[:30],
            "sources": sources,
            "editorialNote": "Cambios en páginas externas sin validar; no implican actualización del incidente.",
        }
        checked += 1
    state["version"] = 1
    state["lastRun"] = NOW.isoformat(timespec="seconds")
    state["lastRunCount"] = checked
    state["pendingCount"] = sum(bool(x.get("pendingEvidence")) for x in records.values())
    state["remainingDue"] = max(0, len(due) - checked)
    state["policy"] = {"maxIncidentsPerRun":MAX_INCIDENTS, "maxSourcesPerIncident":MAX_SOURCES_PER_INCIDENT,
                       "maxElapsedSeconds":MAX_ELAPSED_SECONDS,
                       "editorialChangesAutomatic":False,
                       "note":"Las señales por cambios remotos requieren verificación; no actualizan los incidentes."}
    OUTPUT.write_text(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"checked":checked,"remainingDue":state["remainingDue"],
                      "pendingEvidence":state["pendingCount"]},ensure_ascii=False))


if __name__ == "__main__":
    main()
