"""Exports: a hand-built STIX 2.1 bundle and plain/CSV blocklists.

STIX patterns carry the real (re-fanged) value because they are meant for
machines. Text blocklists for URLs and domains are defanged unless fanged=True
is asked for explicitly (needed when feeding a DNS/proxy blocker).
"""
from __future__ import annotations

import csv
import io
import json
import uuid
from pathlib import Path

from . import NAME, __version__, config, db, defang, timeutil

NAMESPACE = uuid.UUID("6f1c2a4e-0d1b-4c8e-9a43-5e8f0b7c2d10")   # fixed so ids are stable across exports
PRODUCER = "identity--" + str(uuid.uuid5(NAMESPACE, "seclab-threat-intel"))


def sid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, f'{kind}:{key}')}"


def stix_pattern(itype: str, value: str, tags=()) -> str | None:
    v = defang.refang(value).replace("\\", "\\\\").replace("'", "\\'")
    if itype == "ip":
        return f"[{'ipv6-addr' if ':' in v else 'ipv4-addr'}:value = '{v}']"
    if itype == "cidr":
        return f"[{'ipv6-addr' if ':' in v else 'ipv4-addr'}:value = '{v}']"
    if itype == "domain":
        return f"[domain-name:value = '{v}']"
    if itype == "url":
        return f"[url:value = '{v}']"
    if itype == "hash" and "x509-sha1" in tags:
        return f"[x509-certificate:hashes.'SHA-1' = '{v}']"
    if itype == "hash":
        algo = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(len(v))
        return f"[file:hashes.'{algo}' = '{v}']" if algo else None
    return None


def stix_bundle(conn, min_confidence: int = 50, limit: int = 2000) -> dict:
    now = timeutil.iso(db.now())
    objs = [{"type": "identity", "spec_version": "2.1", "id": PRODUCER, "created": now, "modified": now,
             "name": f"seclab {NAME} {__version__}", "identity_class": "system"}]
    inds = db.rows(conn, """SELECT * FROM indicators WHERE context_only=0 AND confidence>=?
                            ORDER BY confidence DESC, last_seen DESC LIMIT ?""", (min_confidence, limit))
    families = {}
    for i in inds:
        tags = db.jload(i["tags"])
        pattern = stix_pattern(i["type"], i["value"], tags)
        if not pattern:
            continue
        iid = sid("indicator", f"{i['type']}:{i['value']}")
        objs.append({
            "type": "indicator", "spec_version": "2.1", "id": iid, "created_by_ref": PRODUCER,
            "created": timeutil.iso(i["first_seen"]) or now, "modified": now,
            "name": f"{i['type']} {i['value']}", "pattern": pattern, "pattern_type": "stix",
            "valid_from": timeutil.iso(i["first_seen"]) or now,
            "indicator_types": ["malicious-activity"] if "phishing" not in tags else ["malicious-activity", "anomalous-activity"],
            "confidence": int(i["confidence"] or 0),
            "labels": sorted(set(db.jload(i["sources"])) | {t for t in tags if ":" not in t})[:20],
        })
        if i["malware"]:
            families.setdefault(i["malware"], []).append(iid)
    for fam, ids in families.items():
        mid = sid("malware", fam)
        objs.append({"type": "malware", "spec_version": "2.1", "id": mid, "created": now, "modified": now,
                     "name": fam, "is_family": True, "created_by_ref": PRODUCER})
        for iid in ids:
            objs.append({"type": "relationship", "spec_version": "2.1", "id": sid("relationship", f"{iid}>{mid}"),
                         "created": now, "modified": now, "relationship_type": "indicates",
                         "source_ref": iid, "target_ref": mid})
        for a in db.rows(conn, """SELECT DISTINCT a.id, a.name, a.attack_id FROM relationships r JOIN actors a ON a.id=r.dst
                                  WHERE r.src=? AND r.rel='family-of'""", (f"malware:{fam}",)):
            aid = sid("intrusion-set", a["id"])
            if not any(o["id"] == aid for o in objs):
                ext = [{"source_name": "mitre-attack", "external_id": a["attack_id"]}] if a["attack_id"] else []
                objs.append({"type": "intrusion-set", "spec_version": "2.1", "id": aid, "created": now,
                             "modified": now, "name": a["name"], "external_references": ext})
            objs.append({"type": "relationship", "spec_version": "2.1", "id": sid("relationship", f"{aid}>{mid}"),
                         "created": now, "modified": now, "relationship_type": "uses", "source_ref": aid, "target_ref": mid})
    for v in db.rows(conn, "SELECT cve, name, description FROM vulnerabilities ORDER BY priority DESC LIMIT 100"):
        objs.append({"type": "vulnerability", "spec_version": "2.1", "id": sid("vulnerability", v["cve"]),
                     "created": now, "modified": now, "name": v["cve"], "description": v["description"] or v["name"],
                     "external_references": [{"source_name": "cve", "external_id": v["cve"]}]})
    return {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": objs}


def blocklist(conn, itype: str, min_confidence: int = 50, fanged: bool = False) -> str:
    rows = conn.execute("""SELECT value FROM indicators WHERE type=? AND context_only=0 AND confidence>=?
                           ORDER BY value""", (itype, min_confidence)).fetchall()
    head = (f"# seclab threat-intel {itype} blocklist, min confidence {min_confidence}, "
            f"generated {timeutil.iso(db.now())}, {len(rows)} entries"
            + ("" if fanged or itype not in ("url", "domain") else ", DEFANGED") + "\n")
    vals = [defang.refang(r[0]) if fanged else r[0] for r in rows]
    return head + "\n".join(vals) + ("\n" if vals else "")


def indicators_csv(conn, min_confidence: int = 0) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "confidence", "sources", "malware", "asn", "country", "first_seen", "last_seen", "tags"])
    for r in conn.execute("""SELECT type, value, confidence, sources, malware, asn, country, first_seen, last_seen, tags
                             FROM indicators WHERE confidence>=? ORDER BY confidence DESC""", (min_confidence,)):
        w.writerow([r["type"], r["value"], r["confidence"], ";".join(db.jload(r["sources"])), r["malware"] or "",
                    r["asn"] or "", r["country"] or "", timeutil.iso(r["first_seen"]), timeutil.iso(r["last_seen"]),
                    ";".join(db.jload(r["tags"]))])
    return buf.getvalue()


def write_all(conn, out_dir: str | None = None, fanged: bool = False) -> list[Path]:
    out = Path(out_dir) if out_dir else config.get().db_path.parent / "exports"
    out.mkdir(parents=True, exist_ok=True)
    paths = []
    p = out / "bundle.stix.json"
    p.write_text(json.dumps(stix_bundle(conn), indent=1))
    paths.append(p)
    for t in ("ip", "cidr", "domain", "url", "hash"):
        p = out / f"blocklist-{t}.txt"
        p.write_text(blocklist(conn, t, fanged=fanged))
        paths.append(p)
    p = out / "indicators.csv"
    p.write_text(indicators_csv(conn))
    paths.append(p)
    return paths
