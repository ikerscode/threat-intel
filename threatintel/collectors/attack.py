"""MITRE ATT&CK Enterprise (STIX 2.1) from github.com/mitre-attack/attack-stix-data.

Extracts tactics, techniques (incl. sub-techniques), groups (intrusion-set),
software (malware + tool) and the `uses` / `subtechnique-of` relationships.
CVE ids mentioned in relationship or group descriptions become
group -> cve "exploits" edges, which is how ATT&CK links groups to CVEs.
Revoked and deprecated objects are skipped.
"""
from __future__ import annotations

import json
import re

from .. import db
from .base import Collector

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
CVE_IN_TEXT = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
CITATION = re.compile(r"\(Citation:[^)]*\)")


def ext_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def ext_url(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


def short(text: str | None, n: int = 400) -> str:
    t = CITATION.sub("", text or "").strip()
    return t if len(t) <= n else t[: n - 1].rsplit(" ", 1)[0] + "..."


def node_for(obj_type: str, attack_id: str) -> str:
    if obj_type == "attack-pattern":
        return f"technique:{attack_id}"
    if obj_type == "intrusion-set":
        return f"attack-group:{attack_id}"
    if obj_type in ("malware", "tool"):
        return f"software:{attack_id}"
    return f"{obj_type}:{attack_id}"


class AttackCollector(Collector):
    name = "attack"
    title = "MITRE ATT&CK Enterprise"
    homepage = "https://attack.mitre.org/"
    licence = "ATT&CK Terms of Use: royalty-free, reproduce with the MITRE copyright notice"
    fixture_files = ("attack-enterprise-trimmed.json",)

    def fetch(self, conn=None):
        return json.loads(self.get(URL).body)

    def normalise(self, raw) -> dict:
        objs = [o for o in raw.get("objects", []) if not o.get("revoked") and not o.get("x_mitre_deprecated")]
        by_id = {o["id"]: o for o in objs}
        tactic_order = []
        for o in objs:
            if o["type"] == "x-mitre-matrix":
                tactic_order = o.get("tactic_refs", [])
        tactics = []
        for o in objs:
            if o["type"] == "x-mitre-tactic":
                ref_ord = tactic_order.index(o["id"]) if o["id"] in tactic_order else 99
                tactics.append({"id": ext_id(o), "shortname": o.get("x_mitre_shortname"), "name": o["name"],
                                "ord": ref_ord})
        techniques, groups, software = [], [], []
        for o in objs:
            aid = ext_id(o)
            if not aid:
                continue
            if o["type"] == "attack-pattern":
                techniques.append({
                    "id": aid, "stix_id": o["id"], "name": o["name"],
                    "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])
                                if p.get("kill_chain_name") == "mitre-attack"],
                    "is_sub": bool(o.get("x_mitre_is_subtechnique")), "parent": aid.split(".")[0] if "." in aid else None,
                    "description": short(o.get("description")), "url": ext_url(o)})
            elif o["type"] == "intrusion-set":
                groups.append({"id": aid, "stix_id": o["id"], "name": o["name"],
                               "aliases": [a for a in o.get("aliases", []) if a != o["name"]],
                               "description": short(o.get("description"), 600), "url": ext_url(o),
                               "cves": sorted({c.upper() for c in CVE_IN_TEXT.findall(o.get("description") or "")})})
            elif o["type"] in ("malware", "tool"):
                software.append({"id": aid, "stix_id": o["id"], "name": o["name"], "type": o["type"],
                                 "aliases": [a for a in o.get("x_mitre_aliases", []) if a != o["name"]],
                                 "description": short(o.get("description")), "url": ext_url(o)})
        rels = []
        for o in objs:
            if o["type"] != "relationship" or o.get("relationship_type") not in ("uses", "subtechnique-of"):
                continue
            s, t = by_id.get(o["source_ref"]), by_id.get(o["target_ref"])
            if not s or not t or not ext_id(s) or not ext_id(t):
                continue
            src, dst = node_for(s["type"], ext_id(s)), node_for(t["type"], ext_id(t))
            rels.append({"src": src, "rel": o["relationship_type"], "dst": dst})
            if s["type"] == "intrusion-set":
                for cve in sorted({c.upper() for c in CVE_IN_TEXT.findall(o.get("description") or "")}):
                    rels.append({"src": src, "rel": "exploits", "dst": f"cve:{cve}",
                                 "note": f"mentioned in ATT&CK relationship to {ext_id(t)}"})
        for g in groups:
            for cve in g["cves"]:
                rels.append({"src": f"attack-group:{g['id']}", "rel": "exploits", "dst": f"cve:{cve}",
                             "note": "mentioned in ATT&CK group description"})
        return {"tactics": tactics, "techniques": techniques, "groups": groups, "software": software,
                "relationships": rels}

    def store(self, conn, rec) -> int:
        conn.execute("DELETE FROM relationships WHERE source='attack'")
        conn.execute("DELETE FROM actor_records WHERE source='attack'")
        for t in rec["tactics"]:
            conn.execute("INSERT OR REPLACE INTO tactics(id, shortname, name, ord) VALUES (?,?,?,?)",
                         (t["id"], t["shortname"], t["name"], t["ord"]))
        for t in rec["techniques"]:
            conn.execute("""INSERT OR REPLACE INTO techniques(id, stix_id, name, tactics, is_sub, parent, description, url)
                            VALUES (?,?,?,?,?,?,?,?)""",
                         (t["id"], t["stix_id"], t["name"], json.dumps(t["tactics"]), int(t["is_sub"]), t["parent"],
                          t["description"], t["url"]))
        for s in rec["software"]:
            conn.execute("""INSERT OR REPLACE INTO software(id, stix_id, name, type, aliases, description, url)
                            VALUES (?,?,?,?,?,?,?)""",
                         (s["id"], s["stix_id"], s["name"], s["type"], json.dumps(s["aliases"]), s["description"], s["url"]))
        for g in rec["groups"]:
            conn.execute("""INSERT OR REPLACE INTO actor_records(source, source_id, name, aliases, description, url, extra)
                            VALUES ('attack',?,?,?,?,?,?)""",
                         (g["id"], g["name"], json.dumps(g["aliases"]), g["description"], g["url"],
                          json.dumps({"stix_id": g["stix_id"]})))
        for r in rec["relationships"]:
            db.add_rel(conn, r["src"], r["rel"], r["dst"], self.name, r.get("note"))
        return len(rec["techniques"]) + len(rec["groups"]) + len(rec["software"]) + len(rec["relationships"])
