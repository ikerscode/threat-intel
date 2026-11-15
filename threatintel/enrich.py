"""Enrichment: match a list of IOCs (or a STIX 2.1 bundle) against collected intel.

Other lab projects post attacker IPs, domains, URLs and file hashes here and get
back a verdict and context for each one. With record=True, IOCs are stored as an
"enrich" sighting (low weight) so they show up in pivots and correlation.
"""
from __future__ import annotations

import re

from . import asn, db, defang
from .correlate import NetblockIndex

STIX_PATTERN = re.compile(
    r"\[\s*(ipv4-addr|ipv6-addr|domain-name|url|file|network-traffic)"
    r"(?::value|:hashes\.'?(?:MD5|SHA-1|SHA-256|SHA1|SHA256)'?|:dst_ref\.value)\s*=\s*'([^']+)'\s*\]", re.I)
SPLIT = re.compile(r"[\s,;]+")


def iocs_from_stix(bundle: dict) -> list[str]:
    """Pull IOC values from indicator patterns and from cyber observables."""
    out = []
    for obj in bundle.get("objects", []):
        t = obj.get("type")
        if t == "indicator":
            out += [m.group(2) for m in STIX_PATTERN.finditer(obj.get("pattern", ""))]
        elif t in ("ipv4-addr", "ipv6-addr", "domain-name", "url") and obj.get("value"):
            out.append(obj["value"])
        elif t == "file":
            out += [h for h in (obj.get("hashes") or {}).values() if isinstance(h, str)]
    return out


def iocs_from_text(text: str) -> list[str]:
    return [t for t in SPLIT.split(text or "") if t and not t.startswith("#")]


def _actors_for_malware(conn, fam: str) -> list[dict]:
    """malware family -> actors that deploy it, directly or through ATT&CK software."""
    actor_ids = {r[0] for r in conn.execute(
        "SELECT dst FROM relationships WHERE src=? AND rel='family-of'", (f"malware:{fam}",))}
    for (sw,) in conn.execute("SELECT dst FROM relationships WHERE src=? AND rel='is'", (f"malware:{fam}",)).fetchall():
        actor_ids |= {r[0] for r in conn.execute(
            "SELECT src FROM relationships WHERE dst=? AND src LIKE 'actor:%' AND rel IN ('uses','deploys')", (sw,))}
    if not actor_ids:
        return []
    ids = sorted(actor_ids)[:15]
    return db.rows(conn, f"SELECT id, name, attack_id FROM actors WHERE id IN ({','.join('?' * len(ids))})", ids)


def verdict(ind: dict | None, inside_drop: str | None) -> str:
    if ind and not ind.get("context_only"):
        c = ind.get("confidence") or 0
        if c >= 60:
            return "malicious"
        if c >= 25:
            return "suspicious"
        return "low-confidence"
    if inside_drop:
        return "suspicious"
    if ind and ind.get("context_only"):
        return "context"
    return "unknown"


def enrich_one(conn, raw: str, nb: NetblockIndex) -> dict:
    itype, value = defang.normalise_ioc(raw)
    res = {"input": raw, "type": itype, "value": value, "match": False}
    if itype not in ("ip", "cidr", "url", "domain", "hash"):
        res["verdict"] = "unsupported"
        return res
    ind = db.one(conn, "SELECT * FROM indicators WHERE type=? AND value=?", (itype, value))
    inside = None
    if itype == "ip":
        inside = nb.find(value)
        res["asn"] = (ind and ind.get("asn") and {"asn": ind["asn"], "as_name": ind["as_name"], "country": ind["country"]}) or asn.lookup(value)
        res["inside_drop"] = inside
    if itype in ("url", "domain"):
        host = defang.url_host(value) if itype == "url" else defang.refang(value)
        from . import psl
        reg = psl.registered_domain(host)
        if reg:
            reg_d = reg if psl.is_ip(reg) else defang.defang_domain(reg)
            res["registered_domain"] = reg_d
            res["related_in_registered_domain"] = conn.execute(
                "SELECT COUNT(*) FROM indicators WHERE reg_domain=? AND context_only=0", (reg_d,)).fetchone()[0]
    if ind:
        res.update(match=True, confidence=ind["confidence"], sources=db.jload(ind["sources"]),
                   tags=db.jload(ind["tags"]), malware=ind["malware"],
                   first_seen=ind["first_seen"], last_seen=ind["last_seen"])
        obs = conn.execute("""SELECT MIN(first_obs), MAX(last_obs), MAX(days_seen) FROM sightings
                              WHERE indicator_id=? AND source != 'enrich'""", (ind["id"],)).fetchone()
        if obs and obs[0]:
            res["observed"] = {"first": obs[0], "last": obs[1], "days_seen": obs[2]}
        pa = conn.execute("SELECT score, brands, reasons FROM phishing_analysis WHERE indicator_id=?", (ind["id"],)).fetchone()
        if pa:
            res["phishing"] = {"score": pa[0], "brands": db.jload(pa[1]), "reasons": db.jload(pa[2])}
        if ind["malware"]:
            res["actors"] = _actors_for_malware(conn, ind["malware"])
    res["verdict"] = verdict(ind, inside)
    return res


def enrich(conn, items: list[str], record: bool = False, reporter: str = "lab", rdap: bool = False) -> dict:
    """Match IOCs. rdap=True also looks up registration data (at most rdap.max_per_request over the network)."""
    from . import rdap as rdap_mod
    nb = NetblockIndex(conn)
    seen, results = set(), []
    for raw in items[:5000]:
        raw = (raw or "").strip()
        if not raw or raw in seen:
            continue
        seen.add(raw)
        results.append(enrich_one(conn, raw, nb))
    budget = int(rdap_mod.settings()["max_per_request"]) if rdap else 0
    for r in results:
        if r["type"] not in ("ip", "domain", "url"):
            continue
        try:
            row = rdap_mod.cached(conn, r["value"])
            stale = not row or (row.get("fetched_at") or 0) < db.now() - float(rdap_mod.settings()["ttl_days"]) * 86400
            if rdap and stale and budget > 0:
                row = rdap_mod.lookup(conn, r["value"])
                budget -= 1
        except Exception as exc:  # optional context: report, never fail the enrichment
            row = {"status": "error", "error": f"{type(exc).__name__}: {exc}"[:200]}
        if row:
            r["rdap"] = rdap_mod.summary(row)
    if record:
        for r in results:
            if r["type"] in ("ip", "domain", "url", "hash"):
                db.upsert_indicator(conn, type=r["type"], value=r["value"], source="enrich",
                                    tags=[f"reported-by:{reporter[:40]}"])
        conn.commit()
    summary = {}
    for r in results:
        summary[r["verdict"]] = summary.get(r["verdict"], 0) + 1
    return {"count": len(results), "summary": summary, "results": results}


def parse_payload(payload) -> list[str]:
    """Accept {"iocs": [...]}, {"text": "..."}, a STIX bundle, or a bare list."""
    if isinstance(payload, list):
        return [str(x) for x in payload]
    if not isinstance(payload, dict):
        return []
    if payload.get("type") == "bundle":
        return iocs_from_stix(payload)
    if isinstance(payload.get("stix"), dict):
        return iocs_from_stix(payload["stix"])
    items = [str(x) for x in payload.get("iocs", [])]
    items += iocs_from_text(payload.get("text", ""))
    return items
