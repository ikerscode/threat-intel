"""Correlation engine.

Runs after collection and is safe to re-run: every derived edge has
source = 'correlate' and is deleted and rebuilt each time.

Steps
1. actors      merge ATT&CK groups and ransomware.live groups into `actors`
               (union-find over normalised names + aliases + curated map)
2. software    link actors to ATT&CK software (ATT&CK "uses", ransomware.live tool
               lists, ransomware family name == software name)
3. malware     link malware family names seen in feeds to ATT&CK software and actors
4. vulns       vendor/product edges come from KEV; here: priority score + ransomware edge
5. indicators  ASN enrichment, DROP containment, confidence score
6. phishing    host, registered domain, brand and hosting edges
7. clusters    shared /24, shared ASN, shared registered domain, IPs inside DROP
"""
from __future__ import annotations

import bisect
import ipaddress
import json
import time
from collections import defaultdict

from . import aliases, asn, db, phishing, scoring

DERIVED = "correlate"


# ------------------------------------------------------------------ helpers

class UnionFind:
    def __init__(self):
        self.parent: dict = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def rel(conn, src, r, dst, note=None):
    db.add_rel(conn, src, r, dst, DERIVED, note)


# ------------------------------------------------------------------ 1. actors

def resolve_actors(conn) -> dict:
    """Merge actor_records into actors. Returns {record (source, id): actor_id}."""
    recs = db.rows(conn, "SELECT * FROM actor_records")
    uf = UnionFind()
    rec_keys: dict[tuple, set] = {}
    key_owner: dict[str, tuple] = {}
    for r in recs:
        rid = (r["source"], r["source_id"])
        keys = {aliases.canonical_group(r["name"])}
        keys |= {aliases.canonical_group(a) for a in db.jload(r["aliases"])}
        keys = {k for k in keys if len(k) >= 3 or k == aliases.norm(r["name"])}
        rec_keys[rid] = keys
        uf.find(rid)
        for k in keys:
            if k in key_owner:
                uf.union(key_owner[k], rid)
            else:
                key_owner[k] = rid
    groups: dict = defaultdict(list)
    for r in recs:
        groups[uf.find((r["source"], r["source_id"]))].append(r)

    conn.execute("DELETE FROM actors")
    conn.execute("DELETE FROM actor_aliases")
    mapping: dict[tuple, str] = {}
    for members in groups.values():
        attack = [m for m in members if m["source"] == "attack"]
        rw = [m for m in members if m["source"] == "ransomware"]
        primary = attack[0] if attack else rw[0]
        key = aliases.canonical_group(primary["name"])
        disp = aliases.display_name(key, "groups") if not attack else None
        actor_id = f"actor:{key}"
        names = set()
        for m in members:
            names.add(m["name"])
            names |= set(db.jload(m["aliases"]))
        name = primary["name"] if attack else (disp or primary["name"])
        kinds = sorted({"attack-group" if m["source"] == "attack" else "ransomware" for m in members})
        desc = primary["description"] or (rw[0]["description"] if rw else "")
        conn.execute(
            """INSERT OR REPLACE INTO actors(id, name, aliases, kinds, attack_id, ransomware_name, description, url)
               VALUES (?,?,?,?,?,?,?,?)""",
            (actor_id, name, json.dumps(sorted(names - {name})), json.dumps(kinds),
             attack[0]["source_id"] if attack else None, json.dumps(sorted(m["name"] for m in rw)),
             desc, primary["url"]))
        for m in members:
            mapping[(m["source"], m["source_id"])] = actor_id
            for k in rec_keys[(m["source"], m["source_id"])]:
                conn.execute("INSERT OR IGNORE INTO actor_aliases(alias, actor_id) VALUES (?, ?)", (k, actor_id))
            if m["source"] == "attack":
                conn.execute("INSERT OR IGNORE INTO actor_aliases(alias, actor_id) VALUES (?, ?)",
                             (m["source_id"].lower(), actor_id))
                rel(conn, actor_id, "same-as", f"attack-group:{m['source_id']}")
            else:
                rel(conn, actor_id, "same-as", f"rwgroup:{m['name']}")
    # Victims: attach to the merged actor.
    alias_map = dict(conn.execute("SELECT alias, actor_id FROM actor_aliases").fetchall())
    for (gname,) in conn.execute("SELECT DISTINCT group_name FROM victims").fetchall():
        aid = alias_map.get(aliases.canonical_group(gname))
        conn.execute("UPDATE victims SET actor_id=? WHERE group_name=?", (aid, gname))
    # Lift source-level edges onto actors.
    for src_prefix, source in (("attack-group:", "attack"), ("rwgroup:", "ransomware")):
        for r in db.rows(conn, "SELECT src, rel, dst, note FROM relationships WHERE src LIKE ? AND source=?",
                         (src_prefix + "%", source)):
            sid = r["src"][len(src_prefix):]
            aid = mapping.get((source, sid))
            if aid:
                rel(conn, aid, r["rel"], r["dst"], r["note"])
    merged = sum(1 for m in groups.values() if len({x["source"] for x in m}) > 1)
    return {"actor_records": len(recs), "actors": len(groups), "merged_across_sources": merged}


# ------------------------------------------------------------------ 2/3. software and malware

def software_index(conn) -> dict[str, str]:
    """normalised name/alias -> software id."""
    idx: dict[str, str] = {}
    for s in db.rows(conn, "SELECT id, name, aliases FROM software"):
        for n in [s["name"], *db.jload(s["aliases"])]:
            for k in (aliases.norm(n), aliases.canonical_malware(n)):
                if k and len(k) >= 3:
                    idx.setdefault(k, s["id"])
    return idx


def link_software_and_malware(conn) -> dict:
    sw_idx = software_index(conn)
    alias_map = dict(conn.execute("SELECT alias, actor_id FROM actor_aliases").fetchall())
    stats = {"tool_links": 0, "family_links": 0, "malware_to_software": 0, "malware_to_actor": 0}
    # ransomware.live tool lists -> software
    for r in db.rows(conn, "SELECT source_id, extra FROM actor_records WHERE source='ransomware'"):
        aid = alias_map.get(aliases.canonical_group(r["source_id"]))
        for tool in db.jload(r["extra"], {}).get("tools", []):
            sid = sw_idx.get(aliases.norm(tool)) or sw_idx.get(aliases.canonical_malware(tool))
            if aid and sid:
                rel(conn, aid, "uses", f"software:{sid}", "ransomware.live tool list")
                stats["tool_links"] += 1
    # ransomware family software (e.g. "LockBit 3.0", "Akira") -> ransomware actor of the same name
    for s in db.rows(conn, "SELECT id, name, aliases, description FROM software WHERE type='malware'"):
        # only ransomware families: avoids "Chaos" the backdoor matching "chaos" the ransomware crew
        if "ransomware" not in (s["description"] or "").lower() and "ransomware" not in s["name"].lower():
            continue
        for n in [s["name"], *db.jload(s["aliases"])]:
            k = aliases.norm(n)
            aid = alias_map.get(aliases.canonical_group(n)) or alias_map.get(aliases.strip_version(k))
            if aid and aid.startswith("actor:"):
                actor = db.one(conn, "SELECT kinds FROM actors WHERE id=?", (aid,))
                if actor and "ransomware" in db.jload(actor["kinds"]):
                    rel(conn, aid, "deploys", f"software:{s['id']}", f"family name match: {n}")
                    stats["family_links"] += 1
                    break
    # malware family keys seen in feeds -> software and actors
    fams = {r[0] for r in conn.execute("SELECT DISTINCT malware FROM indicators WHERE malware IS NOT NULL")}
    fams |= {r[0][len("malware:"):] for r in conn.execute("SELECT DISTINCT dst FROM relationships WHERE dst LIKE 'malware:%'")}
    for fam in sorted(f for f in fams if f):
        canon = aliases.canonical_malware(fam)
        sid = sw_idx.get(canon) or sw_idx.get(fam) or sw_idx.get(aliases.strip_version(canon))
        if sid:
            rel(conn, f"malware:{fam}", "is", f"software:{sid}")
            stats["malware_to_software"] += 1
        aid = alias_map.get(aliases.canonical_group(fam)) or alias_map.get(aliases.strip_version(canon))
        if aid:
            rel(conn, f"malware:{fam}", "family-of", aid)
            stats["malware_to_actor"] += 1
    return stats


def technique_tactic_edges(conn) -> dict:
    short_to_id = dict(conn.execute("SELECT shortname, id FROM tactics").fetchall())
    n = 0
    for t in db.rows(conn, "SELECT id, tactics, parent FROM techniques"):
        for short in db.jload(t["tactics"]):
            if short in short_to_id:
                rel(conn, f"technique:{t['id']}", "in-tactic", f"tactic:{short_to_id[short]}")
                n += 1
        if t["parent"]:
            rel(conn, f"technique:{t['id']}", "subtechnique-of", f"technique:{t['parent']}")
    return {"technique_tactic_edges": n}


# ------------------------------------------------------------------ 4. vulnerabilities

def score_vulnerabilities(conn) -> dict:
    n = 0
    now = time.time()
    for v in db.rows(conn, "SELECT cve, in_kev, epss, cvss, ransomware_use, date_added FROM vulnerabilities"):
        known = (v["ransomware_use"] or "").lower() == "known"
        total, parts = scoring.vuln_priority(in_kev=bool(v["in_kev"]), epss=v["epss"], cvss=v["cvss"],
                                             ransomware=known, date_added=v["date_added"], now=now)
        conn.execute("UPDATE vulnerabilities SET priority=?, priority_parts=? WHERE cve=?",
                     (total, json.dumps(parts), v["cve"]))
        if known:
            rel(conn, f"cve:{v['cve']}", "used-in", "campaign:known-ransomware-use", "CISA KEV knownRansomwareCampaignUse")
        n += 1
    return {"vulns_scored": n}


# ------------------------------------------------------------------ 5. indicators

class NetblockIndex:
    """Sorted DROP ranges for fast IP containment checks."""

    def __init__(self, conn):
        self.ranges = {4: [], 6: []}
        for r in conn.execute("SELECT cidr, start_int, end_int, version FROM netblocks"):
            self.ranges[r["version"]].append((int(r["start_int"]), int(r["end_int"]), r["cidr"]))
        for v in self.ranges:
            self.ranges[v].sort()
        self.starts = {v: [x[0] for x in self.ranges[v]] for v in self.ranges}

    def find(self, ip: str) -> str | None:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        i = bisect.bisect_right(self.starts[a.version], int(a)) - 1
        # DROP blocks do not overlap, so the closest start is the only candidate
        if i >= 0 and int(a) <= self.ranges[a.version][i][1]:
            return self.ranges[a.version][i][2]
        return None


def score_indicators(conn) -> dict:
    nb = NetblockIndex(conn)
    now = time.time()
    sightings: dict[int, list] = defaultdict(list)
    for s in conn.execute("SELECT indicator_id, source, extra FROM sightings"):
        w = scoring.SOURCE_WEIGHTS.get(s["source"], 0.5)
        if s["source"] == "threatfox":
            conf = db.jload(s["extra"], {}).get("confidence")
            if isinstance(conf, (int, float)):
                w = max(0.1, min(1.0, conf / 100))
        sightings[s["indicator_id"]].append((s["source"], w))
    stats = {"scored": 0, "asn_enriched": 0, "in_drop": 0}
    for ind in db.rows(conn, "SELECT id, type, value, last_seen, asn, tags FROM indicators"):
        weights = [w for _, w in sightings.get(ind["id"], [])]
        tags = set(db.jload(ind["tags"]))
        updates = {}
        if ind["type"] == "ip":
            if ind["asn"] is None:
                hit = asn.lookup(ind["value"])
                if hit:
                    updates.update(asn=hit["asn"], as_name=hit["as_name"], country=hit["country"])
                    stats["asn_enriched"] += 1
            block = nb.find(ind["value"])
            if block:
                weights.append(scoring.SOURCE_WEIGHTS["drop-containment"])
                tags.add("in-drop")
                rel(conn, f"ip:{ind['value']}", "inside", f"cidr:{block}", "Spamhaus DROP netblock")
                stats["in_drop"] += 1
        score, _ = scoring.indicator_confidence(ind["type"], weights, ind["last_seen"], now)
        context_only = int(all(w == 0 for w in weights)) if weights else 1
        updates.update(confidence=score, context_only=context_only, tags=json.dumps(sorted(tags)))
        cols = ", ".join(f"{k}=?" for k in updates)
        conn.execute(f"UPDATE indicators SET {cols} WHERE id=?", (*updates.values(), ind["id"]))
        stats["scored"] += 1
    return stats


def infrastructure_edges(conn) -> dict:
    """ip -> /24 and ASN, url -> host -> registered domain (malicious indicators only)."""
    n = 0
    for ind in db.rows(conn, "SELECT type, value, asn, host, reg_domain FROM indicators WHERE context_only=0 AND type IN ('ip','url','domain')"):
        node = f"{ind['type']}:{ind['value']}"
        if ind["type"] == "ip":
            try:
                a = ipaddress.ip_address(ind["value"])
            except ValueError:
                continue
            if a.version == 4:
                rel(conn, node, "in-subnet", f"net24:{ipaddress.ip_network(f'{a}/24', strict=False)}")
            if ind["asn"]:
                rel(conn, node, "announced-by", f"asn:AS{ind['asn']}")
        elif ind["type"] == "url" and ind["host"]:
            host_type = "ip" if ind["host"][0].isdigit() and "[.]" not in ind["host"] else "domain"
            rel(conn, node, "hosted-on", f"{host_type}:{ind['host']}")
        if ind["type"] == "domain" and ind["reg_domain"] and ind["reg_domain"] != ind["value"]:
            rel(conn, node, "subdomain-of", f"regdomain:{ind['reg_domain']}")
        elif ind["type"] == "domain" and ind["reg_domain"]:
            rel(conn, node, "is-registered-domain", f"regdomain:{ind['reg_domain']}")
        n += 1
    return {"infra_edges_from": n}


# ------------------------------------------------------------------ 6. phishing

def analyse_phishing(conn) -> dict:
    n = 0
    for ind in db.rows(conn, "SELECT id, value, tags FROM indicators WHERE type='url' AND tags LIKE '%phishing%'"):
        info = phishing.analyse(ind["value"])
        tags = {t for t in db.jload(ind["tags"]) if not t.startswith(("brand:", "hosting:"))}
        for b in info["brands"]:
            tags.add(f"brand:{b}")
            rel(conn, f"url:{ind['value']}", "impersonates", f"brand:{b}")
        if info["hosting"]:
            tags.add(f"hosting:{info['hosting']}")
        conn.execute("UPDATE indicators SET tags=? WHERE id=?", (json.dumps(sorted(tags)), ind["id"]))
        n += 1
    return {"phishing_urls": n}


# ------------------------------------------------------------------ 7. clusters

def build_clusters(conn, min_size: int = 2) -> dict:
    conn.execute("DELETE FROM clusters")
    inds = db.rows(conn, "SELECT type, value, asn, as_name, reg_domain, malware, tags, sources FROM indicators WHERE context_only=0")
    buckets: dict[tuple, list] = defaultdict(list)
    for i in inds:
        if i["type"] == "ip":
            try:
                a = ipaddress.ip_address(i["value"])
            except ValueError:
                continue
            if a.version == 4:
                buckets[("shared-/24", str(ipaddress.ip_network(f"{a}/24", strict=False)))].append(i)
            if i["asn"]:
                buckets[("shared-asn", f"AS{i['asn']} {i['as_name'] or ''}".strip())].append(i)
            if "in-drop" in db.jload(i["tags"]):
                buckets[("inside-drop", "Spamhaus DROP")].append(i)
        elif i["type"] == "url" and i["reg_domain"]:
            # count URLs only: the host-domain indicator derived from each URL would double count
            buckets[("shared-registered-domain", i["reg_domain"])].append(i)
    n = 0
    for (kind, key), members in buckets.items():
        uniq = {m["value"]: m for m in members}
        if len(uniq) < min_size and kind != "inside-drop":
            continue
        fams = sorted({m["malware"] for m in uniq.values() if m["malware"]})
        conn.execute("INSERT INTO clusters(kind, key, size, members, families) VALUES (?,?,?,?,?)",
                     (kind, key, len(uniq), json.dumps(sorted(uniq)[:200]), json.dumps(fams)))
        n += 1
    return {"clusters": n}


# ------------------------------------------------------------------ entry point

def run(conn) -> dict:
    t0 = time.time()
    conn.execute("DELETE FROM relationships WHERE source=?", (DERIVED,))
    stats = {}
    stats.update(resolve_actors(conn))
    stats.update(link_software_and_malware(conn))
    stats.update(technique_tactic_edges(conn))
    stats.update(score_vulnerabilities(conn))
    stats.update(score_indicators(conn))
    stats.update(infrastructure_edges(conn))
    stats.update(analyse_phishing(conn))
    stats.update(build_clusters(conn))
    stats["derived_edges"] = conn.execute("SELECT COUNT(*) FROM relationships WHERE source=?", (DERIVED,)).fetchone()[0]
    stats["seconds"] = round(time.time() - t0, 2)
    db.set_meta(conn, "last_correlate", {"at": time.time(), **stats})
    conn.commit()
    return stats
