"""CIRCL OSINT MISP feed: the manifest plus a capped number of recent events.

Source: https://www.circl.lu/doc/misp/feed-osint/ (no key). manifest.json lists
about 1 700 events (uuid -> info, date, org, tags, timestamp). We take the
`events` most recently updated ones whose file is at most `event_max_bytes`,
and from each event keep up to `attr_limit` attributes flagged to_ids
(IPs, domains, hostnames, URLs, file hashes).

Safety: MISP events can embed attachments (screenshots, and sometimes zipped
malware samples) as base64 in a "data" field. The fetcher's transform hook
strips every attachment and malware-sample attribute and every "data" field in
memory before the body is cached, so nothing of the kind is written to disk or
stored. Event size is capped before download (Content-Length) and while
streaming. URLs and domains are stored defanged and never visited.
"""
from __future__ import annotations

import ipaddress
import json

from .. import aliases, db, defang, psl, timeutil
from ..fetch import FetchError
from .base import Collector

BASE = "https://www.circl.lu/doc/misp/feed-osint/"
DROP_TYPES = {"malware-sample", "attachment"}
KEEP_TYPES = {"ip-dst", "ip-src", "ip-dst|port", "ip-src|port", "domain", "hostname", "domain|ip", "url",
              "md5", "sha1", "sha256", "filename|md5", "filename|sha1", "filename|sha256"}
# MISP galaxy tags that name a malware family or a threat actor
MALWARE_GALAXIES = ("malpedia", "mitre-malware", "ransomware", "tool", "mitre-tool", "rat", "stealer",
                    "banker", "botnet", "backdoor", "android")
ACTOR_GALAXIES = ("threat-actor", "mitre-intrusion-set", "microsoft-activity-group")


def strip_attachments(body: bytes) -> bytes:
    """Remove embedded files from a MISP event before it is cached (see module doc)."""
    try:
        doc = json.loads(body)
    except ValueError:
        return body

    def clean(attrs):
        out = []
        for a in attrs or []:
            if a.get("type") in DROP_TYPES:
                continue
            a.pop("data", None)
            out.append(a)
        return out

    ev = doc.get("Event", doc)
    ev["Attribute"] = clean(ev.get("Attribute"))
    for obj in ev.get("Object") or []:
        obj["Attribute"] = clean(obj.get("Attribute"))
    return json.dumps(doc).encode()


def galaxy(tag: str) -> tuple[str, str] | None:
    """'misp-galaxy:threat-actor="Turla Group"' -> ('threat-actor', 'Turla Group')."""
    if not tag.startswith("misp-galaxy:") or "=" not in tag:
        return None
    kind, _, value = tag[len("misp-galaxy:"):].partition("=")
    return kind, value.strip('"')


def tag_links(tags: list[str]) -> dict:
    """Malware families, actor names and ATT&CK technique ids named in event tags."""
    out = {"malware": set(), "actors": set(), "techniques": set()}
    for t in tags:
        g = galaxy(t)
        if not g:
            continue
        kind, value = g
        name = value.split(" - ")[0].strip()
        if kind in ACTOR_GALAXIES:
            out["actors"].add(name)
        elif kind in MALWARE_GALAXIES:
            fam = aliases.canonical_malware(name)
            if fam and not aliases.is_generic_tag(name):
                out["malware"].add(fam)
        elif "attack-pattern" in kind and " - T" in value:
            tid = value.rsplit(" - ", 1)[1].strip()
            if tid[:1] == "T" and tid[1:5].isdigit():
                out["techniques"].add(tid)
    return {k: sorted(v) for k, v in out.items()}


def _public_ip(value: str) -> str | None:
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return None
    return None if (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast) else str(ip)


def attribute_iocs(a: dict) -> list[tuple[str, str]]:
    """One MISP attribute -> [(indicator type, stored value)]."""
    t, v = a.get("type", ""), str(a.get("value") or "").strip()
    if not v or t not in KEEP_TYPES:
        return []
    if t in ("ip-dst", "ip-src"):
        ip = _public_ip(v)
        return [("ip", ip)] if ip else []
    if t.endswith("|port"):
        ip = _public_ip(v.rsplit("|", 1)[0])
        return [("ip", ip)] if ip else []
    if t in ("domain", "hostname"):
        host = defang.refang(v).lower().strip(".")
        return [("domain", defang.defang_domain(host))] if defang.DOMAIN_RE.match(host) else []
    if t == "domain|ip":
        d, _, ip = v.partition("|")
        out = attribute_iocs({"type": "domain", "value": d})
        return out + attribute_iocs({"type": "ip-dst", "value": ip})
    if t == "url":
        u = defang.canonical_url(v)
        return [("url", defang.defang_url(u))] if defang.url_host(u) else []
    h = v.rsplit("|", 1)[-1].lower()
    return [("hash", h)] if defang.HASH_RE.match(h) else []


class CirclOsintCollector(Collector):
    name = "circl"
    title = "CIRCL OSINT MISP feed"
    homepage = "https://www.circl.lu/doc/misp/feed-osint/"
    licence = "Public OSINT feed published by CIRCL; events are TLP:CLEAR (check each event's tags)"
    fixture_files = ("circl-osint.json",)

    def fetch(self, conn=None):
        cfg = self.cfg
        manifest = json.loads(self.get(BASE + "manifest.json", max_bytes=8_000_000).body)
        newest = sorted(manifest.items(), key=lambda kv: int(kv[1].get("timestamp") or 0), reverse=True)
        want, cap = int(cfg.get("events", 10)), int(cfg.get("event_max_bytes", 2_500_000))
        events, chosen = [], {}
        for uuid, meta in newest[: want * 3]:
            if len(events) >= want:
                break
            try:
                res = self.get(f"{BASE}{uuid}.json", max_bytes=cap, transform=strip_attachments)
            except FetchError as exc:
                if "byte cap" in str(exc):
                    self.notes.append("skipped oversized event")
                    continue
                raise
            events.append(json.loads(res.body))
            chosen[uuid] = meta
        return {"manifest": chosen, "events": events}

    def normalise(self, raw) -> dict:
        limit = int(self.cfg.get("attr_limit", 300))
        out = []
        for doc in raw.get("events", []):
            ev = doc.get("Event", doc)
            attrs = list(ev.get("Attribute") or [])
            for obj in ev.get("Object") or []:
                attrs += obj.get("Attribute") or []
            tags = [t.get("name", "") for t in ev.get("Tag") or [] if t.get("name")]
            iocs, seen = [], set()
            for a in attrs:
                if not a.get("to_ids") or a.get("type") in DROP_TYPES:
                    continue
                for itype, value in attribute_iocs(a):
                    if (itype, value) in seen:
                        continue
                    seen.add((itype, value))
                    iocs.append({"type": itype, "value": value, "category": a.get("category"),
                                 "ts": timeutil.parse(a.get("timestamp")) or timeutil.parse(ev.get("timestamp"))})
            out.append({
                "uuid": ev.get("uuid"), "info": (ev.get("info") or "")[:300], "date": ev.get("date"),
                "org": (ev.get("Orgc") or {}).get("name"), "threat_level": int(ev.get("threat_level_id") or 0),
                "timestamp": timeutil.parse(ev.get("timestamp")), "tags": tags, "attributes": len(attrs),
                "iocs": iocs[:limit], "links": tag_links(tags),
            })
        return {"events": [e for e in out if e["uuid"]]}

    def store(self, conn, records) -> int:
        n = 0
        for e in records["events"]:
            conn.execute("""INSERT OR REPLACE INTO misp_events(uuid, source, info, date, org, threat_level, tags,
                            timestamp, attributes, stored) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                         (e["uuid"], self.name, e["info"], e["date"], e["org"], e["threat_level"],
                          json.dumps(e["tags"]), e["timestamp"], e["attributes"], len(e["iocs"])))
            node = f"event:{e['uuid']}"
            fams = e["links"]["malware"]
            for i in e["iocs"]:
                host = reg = None
                if i["type"] == "url":
                    h = defang.url_host(i["value"])
                    host = h if psl.is_ip(h) else defang.defang_domain(h)
                    reg = psl.registered_domain(h) if psl.is_ip(h) else defang.defang_domain(psl.registered_domain(h))
                elif i["type"] == "domain":
                    reg = defang.defang_domain(psl.registered_domain(defang.refang(i["value"])))
                db.upsert_indicator(conn, type=i["type"], value=i["value"], source=self.name, first_seen=i["ts"],
                                    last_seen=i["ts"], tags=["osint", "misp-event"], host=host, reg_domain=reg,
                                    malware=fams[0] if len(fams) == 1 else None,
                                    extra={"event": e["uuid"], "info": e["info"][:120], "category": i["category"]})
                db.add_rel(conn, f"{i['type']}:{i['value']}", "reported-in", node, self.name)
                n += 1
            for fam in fams:
                db.add_rel(conn, node, "mentions", f"malware:{fam}", self.name)
            for tid in e["links"]["techniques"]:
                db.add_rel(conn, node, "uses", f"technique:{tid}", self.name)
        return n
