"""Pivot search: any value in, everything linked out (tables + graph).

A search value is classified (defang.detect), resolved to a start node such as
"cve:CVE-2023-4966" or "actor:lockbit", then a breadth-first walk over the
relationships table collects neighbours in both directions. High-degree nodes
(a vendor with 300 CVEs, a technique used by 100 groups) are capped so the
graph stays readable.
"""
from __future__ import annotations

import json
from collections import deque

from . import aliases, asn, db, defang

MAX_NODES = 120
# Hub nodes shared by many unrelated entities. They are shown but not walked
# through (unless they are the search itself), otherwise "uses T1486" would make
# every ransomware crew look linked to every other one.
LEAF_TYPES = {"technique", "tactic", "campaign", "vendor", "brand"}
# Typed node ids accepted verbatim by search (the HUD graph sends these on click).
NODE_PREFIXES = {"actor", "attack-group", "rwgroup", "technique", "tactic", "software", "malware", "cve", "ip", "cidr",
                 "url", "domain", "regdomain", "hash", "asn", "net24", "vendor", "product", "brand", "campaign"}
FANOUT_START = 60
FANOUT = 12


def node_type(node: str) -> str:
    return node.split(":", 1)[0]


def label_for(conn, node: str) -> str:
    kind, _, key = node.partition(":")
    q = {
        "technique": "SELECT name FROM techniques WHERE id=?",
        "software": "SELECT name FROM software WHERE id=?",
        "actor": "SELECT name FROM actors WHERE id=?",
        "tactic": "SELECT name FROM tactics WHERE id=?",
    }.get(kind)
    if q:
        lookup = node if kind == "actor" else key
        r = conn.execute(q, (lookup,)).fetchone()
        if r:
            return f"{key} {r[0]}" if kind in ("technique", "software") else r[0]
    if kind == "attack-group":
        r = conn.execute("SELECT name FROM actor_records WHERE source='attack' AND source_id=?", (key,)).fetchone()
        return f"{key} {r[0]}" if r else key
    return key


# ------------------------------------------------------------------ resolution

def resolve(conn, value: str) -> tuple[str, list[str]]:
    """Return (kind, [start nodes])."""
    prefix, sep, rest = value.strip().partition(":")
    if sep and prefix in NODE_PREFIXES and not rest.startswith("//"):
        node = f"{prefix}:{rest}"
        if prefix == "actor" or conn.execute("SELECT 1 FROM relationships WHERE src=? OR dst=? LIMIT 1", (node, node)).fetchone():
            return "node", [node]
    kind = defang.detect(value)
    v = defang.refang(value).strip()
    alias_map = lambda k: conn.execute("SELECT actor_id FROM actor_aliases WHERE alias=?", (k,)).fetchone()
    if kind == "cve":
        return kind, [f"cve:{v.upper()}"]
    if kind == "technique":
        return kind, [f"technique:{v.upper()}"]
    if kind == "tactic":
        return kind, [f"tactic:{v.upper()}"]
    if kind == "attack-group":
        r = alias_map(v.lower())
        return kind, [r[0] if r else f"attack-group:{v.upper()}"]
    if kind == "software":
        return kind, [f"software:{v.upper()}"]
    if kind in ("ip", "cidr", "url", "domain", "hash"):
        itype, stored = defang.normalise_ioc(v)
        nodes = [f"{itype}:{stored}"]
        if itype == "url":
            host = defang.url_host(stored)
            nodes.append(f"ip:{host}" if defang.detect(host) == "ip" else f"domain:{defang.defang_domain(host)}")
        if itype == "domain":
            from . import psl
            reg = psl.registered_domain(defang.refang(stored))
            if reg and defang.defang_domain(reg) != stored:
                nodes.append(f"regdomain:{defang.defang_domain(reg)}")
            else:
                nodes.append(f"regdomain:{stored}")
        return itype, nodes
    if kind == "asn":
        return kind, [f"asn:{v.upper()}"]
    # free text: actor, malware family, software name, technique name, vendor, brand
    nodes = []
    r = alias_map(aliases.canonical_group(v))
    if r:
        nodes.append(r[0])
    fam = aliases.canonical_malware(v)
    if conn.execute("SELECT 1 FROM relationships WHERE src=? OR dst=? LIMIT 1", (f"malware:{fam}",) * 2).fetchone():
        nodes.append(f"malware:{fam}")
    for s in db.rows(conn, "SELECT id, name, aliases FROM software"):
        if aliases.norm(s["name"]) == aliases.norm(v) or aliases.norm(v) in {aliases.norm(a) for a in db.jload(s["aliases"])}:
            nodes.append(f"software:{s['id']}")
            break
    for prefix in ("vendor:", "brand:"):
        node = prefix + v.lower()
        if conn.execute("SELECT 1 FROM relationships WHERE src=? OR dst=? LIMIT 1", (node, node)).fetchone():
            nodes.append(node)
    if not nodes:
        t = conn.execute("SELECT id FROM techniques WHERE lower(name)=?", (v.lower(),)).fetchone()
        if t:
            nodes.append(f"technique:{t[0]}")
    return ("name" if nodes else "unknown"), list(dict.fromkeys(nodes))


def suggestions(conn, value: str, limit: int = 12) -> list[dict]:
    like = f"%{value.strip()}%"
    out = []
    out += [{"type": "actor", "value": r["name"]} for r in conn.execute("SELECT name FROM actors WHERE name LIKE ? OR aliases LIKE ? LIMIT 5", (like, like))]
    out += [{"type": "software", "value": r["name"]} for r in conn.execute("SELECT name FROM software WHERE name LIKE ? LIMIT 4", (like,))]
    out += [{"type": "technique", "value": r["id"] + " " + r["name"]} for r in conn.execute("SELECT id, name FROM techniques WHERE name LIKE ? LIMIT 4", (like,))]
    out += [{"type": "cve", "value": r["cve"]} for r in conn.execute("SELECT cve FROM vulnerabilities WHERE product LIKE ? OR vendor LIKE ? OR name LIKE ? LIMIT 4", (like, like, like))]
    return out[:limit]


# ------------------------------------------------------------------ walk

def neighbours(conn, node: str, cap: int) -> list[tuple[str, str, str, str]]:
    """[(src, rel, dst, source)] touching node, capped, de-duplicated."""
    rows = conn.execute(
        "SELECT src, rel, dst, source FROM relationships WHERE src=? UNION "
        "SELECT src, rel, dst, source FROM relationships WHERE dst=? LIMIT ?", (node, node, cap * 4)).fetchall()
    # prefer correlate/attack edges (more meaningful) and skip raw source-level duplicates
    rows = sorted(rows, key=lambda r: (r[0].startswith(("attack-group:", "rwgroup:")), r[3] != "correlate"))
    return [tuple(r) for r in rows[:cap]]


def walk(conn, starts: list[str], depth: int = 2) -> tuple[list[str], list[dict]]:
    leaf_types = set(LEAF_TYPES)
    if any(node_type(s) == "actor" for s in starts):
        # from an actor, shared tooling (Mimikatz, PsExec...) would link half the actor table
        leaf_types.add("software")
    seen = list(dict.fromkeys(starts))
    seen_set = set(seen)
    links, link_set = [], set()
    queue = deque((s, 0) for s in starts)
    while queue and len(seen) < MAX_NODES:
        node, d = queue.popleft()
        if d >= depth or (d > 0 and node_type(node) in leaf_types):
            continue
        for src, r, dst, source in neighbours(conn, node, FANOUT_START if d == 0 else FANOUT):
            other = dst if src == node else src
            # ATT&CK/ransomware source-level group nodes are folded into actors; skip them past depth 0
            if node_type(other) in ("attack-group", "rwgroup") and d > 0:
                continue
            if other not in seen_set:
                if len(seen) >= MAX_NODES:
                    break
                seen.append(other)
                seen_set.add(other)
                queue.append((other, d + 1))
            key = (src, r, dst)
            if key not in link_set:
                link_set.add(key)
                links.append({"source": src, "target": dst, "rel": r, "origin": source})
    return seen, links


# ------------------------------------------------------------------ entity details

def entity_details(conn, node: str) -> dict | None:
    kind, _, key = node.partition(":")
    if kind == "cve":
        v = db.one(conn, "SELECT * FROM vulnerabilities WHERE cve=?", (key,))
        if v:
            v["priority_parts"] = db.jload(v["priority_parts"], {})
            v["cwes"] = db.jload(v["cwes"])
        return v
    if kind == "technique":
        return db.one(conn, "SELECT * FROM techniques WHERE id=?", (key,))
    if kind == "tactic":
        return db.one(conn, "SELECT * FROM tactics WHERE id=?", (key,))
    if kind == "software":
        return db.one(conn, "SELECT * FROM software WHERE id=?", (key,))
    if kind == "actor":
        a = db.one(conn, "SELECT * FROM actors WHERE id=?", (node,))
        if a:
            for k in ("aliases", "kinds", "ransomware_name"):
                a[k] = db.jload(a[k])
            from .queries import anchor
            ref = anchor(conn)
            a["activity_anchor"] = ref
            a["victims_7d"] = conn.execute("SELECT COUNT(*) FROM victims WHERE actor_id=? AND discovered > date(?, '-7 day')", (node, ref)).fetchone()[0]
            a["victims_30d"] = conn.execute("SELECT COUNT(*) FROM victims WHERE actor_id=? AND discovered > date(?, '-30 day')", (node, ref)).fetchone()[0]
            a["victims_total"] = conn.execute("SELECT COUNT(*) FROM victims WHERE actor_id=?", (node,)).fetchone()[0]
        return a
    if kind in ("ip", "cidr", "url", "domain", "hash"):
        i = db.one(conn, "SELECT * FROM indicators WHERE type=? AND value=?", (kind, key))
        if i:
            i["sources"] = db.jload(i["sources"])
            i["tags"] = db.jload(i["tags"])
            i["sightings"] = db.rows(conn, "SELECT source, first_seen, last_seen, malware, extra FROM sightings WHERE indicator_id=?", (i["id"],))
            for s in i["sightings"]:
                s["extra"] = db.jload(s["extra"], {})
        elif kind == "ip":
            ctx = asn.lookup(key)
            from .correlate import NetblockIndex
            block = NetblockIndex(conn).find(key)
            i = {"type": "ip", "value": key, "known": False, "asn": ctx, "inside_drop": block}
        return i
    if kind == "malware":
        n = conn.execute("SELECT COUNT(*) FROM indicators WHERE malware=?", (key,)).fetchone()[0]
        return {"family": key, "display": aliases.display_name(key) or key, "indicators": n}
    return None


def linked_tables(conn, nodes: list[str], start: list[str]) -> dict[str, list]:
    groups: dict[str, list] = {}
    for n in nodes:
        if n in start:
            continue
        groups.setdefault(node_type(n), []).append(n)
    out: dict[str, list] = {}
    if "actor" in groups:
        out["actors"] = []
        for n in groups["actor"]:
            a = db.one(conn, "SELECT id, name, kinds, attack_id FROM actors WHERE id=?", (n,))
            if a:
                a["kinds"] = db.jload(a["kinds"])
                out["actors"].append(a)
    if "technique" in groups:
        ids = [n.split(":", 1)[1] for n in groups["technique"]]
        out["techniques"] = db.rows(conn, f"SELECT id, name, tactics FROM techniques WHERE id IN ({','.join('?' * len(ids))}) ORDER BY id", ids)
        for t in out["techniques"]:
            t["tactics"] = db.jload(t["tactics"])
    if "software" in groups:
        ids = [n.split(":", 1)[1] for n in groups["software"]]
        out["software"] = db.rows(conn, f"SELECT id, name, type FROM software WHERE id IN ({','.join('?' * len(ids))})", ids)
    if "cve" in groups:
        ids = [n.split(":", 1)[1] for n in groups["cve"]]
        out["vulnerabilities"] = db.rows(conn, f"SELECT cve, vendor, product, priority, ransomware_use, epss, cvss FROM vulnerabilities WHERE cve IN ({','.join('?' * len(ids))}) ORDER BY priority DESC", ids)
        known = {v["cve"] for v in out["vulnerabilities"]}
        out["vulnerabilities"] += [{"cve": i, "vendor": "", "product": "(not in KEV)", "priority": None} for i in ids if i not in known]
    ind_nodes = [n for t in ("ip", "url", "domain", "hash", "cidr") for n in groups.get(t, [])]
    if ind_nodes:
        out["indicators"] = []
        for n in ind_nodes:
            t, _, v = n.partition(":")
            r = db.one(conn, "SELECT type, value, confidence, malware, sources, asn, country FROM indicators WHERE type=? AND value=?", (t, v))
            if r:
                r["sources"] = db.jload(r["sources"])
                out["indicators"].append(r)
            else:
                out["indicators"].append({"type": t, "value": v, "confidence": None})
    other = [n for t, ns in groups.items() if t not in ("actor", "technique", "software", "cve", "ip", "url", "domain", "hash", "cidr") for n in ns]
    if other:
        out["other"] = [{"type": node_type(n), "value": n.split(":", 1)[1]} for n in other]
    for s in start:
        if s.startswith("actor:"):
            out["recent_victims"] = db.rows(conn, "SELECT victim, sector, country, discovered, group_name FROM victims WHERE actor_id=? ORDER BY discovered DESC LIMIT 25", (s,))
            out["sectors"] = db.rows(conn, "SELECT sector, COUNT(*) n FROM victims WHERE actor_id=? GROUP BY sector ORDER BY n DESC LIMIT 10", (s,))
            out["countries"] = db.rows(conn, "SELECT country, COUNT(*) n FROM victims WHERE actor_id=? GROUP BY country ORDER BY n DESC LIMIT 10", (s,))
        if s.startswith("tactic:"):
            short = conn.execute("SELECT shortname FROM tactics WHERE id=?", (s.split(':', 1)[1],)).fetchone()
            if short:
                out["techniques"] = db.rows(conn, "SELECT id, name, tactics FROM techniques WHERE tactics LIKE ? AND is_sub=0", (f'%"{short[0]}"%',))
                for t in out["techniques"]:
                    t["tactics"] = db.jload(t["tactics"])
    return out


def search(conn, value: str, depth: int = 2) -> dict:
    kind, starts = resolve(conn, value)
    entity = None
    for s in starts:
        entity = entity_details(conn, s)
        if entity:
            break
    nodes, links = walk(conn, starts, depth=depth) if starts else ([], [])
    found = bool(entity) or len(nodes) > len(starts)
    graph_nodes = [{"id": n, "label": label_for(conn, n), "type": node_type(n), "start": n in starts} for n in nodes] if found else []
    return {
        "query": value, "kind": kind, "start_nodes": starts, "found": found,
        "entity": entity,
        "linked": linked_tables(conn, nodes, starts) if found else {},
        "graph": {"nodes": graph_nodes, "links": links if found else []},
        "suggestions": [] if found else suggestions(conn, value),
    }


def to_json(obj) -> str:
    return json.dumps(obj, default=str)
