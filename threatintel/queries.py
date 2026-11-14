"""Read-only queries shared by the HTTP API and the intelligence brief."""
from __future__ import annotations

import json
from collections import Counter, defaultdict

from . import collectors, db, scoring, timeutil


def anchor(conn, what: str = "victims") -> str:
    """Reference date for "last N days" windows.

    Normally today. If the newest data point is older (offline fixtures, a feed that
    stopped), windows are anchored on the newest data instead so they are not empty,
    and the HUD/brief print the anchor date.
    """
    sql = {"victims": "SELECT MAX(substr(discovered,1,10)) FROM victims",
           "kev": "SELECT MAX(date_added) FROM vulnerabilities"}[what]
    latest = conn.execute(sql).fetchone()[0]
    today = timeutil.iso_date(db.now())
    return min(latest, today) if latest else today


def counts(conn) -> dict:
    q = lambda sql: conn.execute(sql).fetchone()[0]
    return {
        "indicators": q("SELECT COUNT(*) FROM indicators WHERE context_only=0"),
        "context_ips": q("SELECT COUNT(*) FROM indicators WHERE context_only=1"),
        "c2_ips": q("SELECT COUNT(*) FROM indicators WHERE type='ip' AND tags LIKE '%\"c2\"%'"),
        "phishing_urls": q("SELECT COUNT(*) FROM indicators WHERE type='url' AND tags LIKE '%\"phishing\"%'"),
        "drop_netblocks": q("SELECT COUNT(*) FROM netblocks"),
        "vulnerabilities": q("SELECT COUNT(*) FROM vulnerabilities"),
        "kev_ransomware": q("SELECT COUNT(*) FROM vulnerabilities WHERE ransomware_use='Known'"),
        "actors": q("SELECT COUNT(*) FROM actors"),
        "merged_actors": q("SELECT COUNT(*) FROM actors WHERE kinds LIKE '%attack-group%' AND kinds LIKE '%ransomware%'"),
        "techniques": q("SELECT COUNT(*) FROM techniques"),
        "software": q("SELECT COUNT(*) FROM software"),
        "victims": q("SELECT COUNT(*) FROM victims"),
        "relationships": q("SELECT COUNT(*) FROM relationships"),
        "clusters": q("SELECT COUNT(*) FROM clusters"),
    }


def top_vulns(conn, limit: int = 25, ransomware_only: bool = False, q: str = "") -> list[dict]:
    where, params = ["1=1"], []
    if ransomware_only:
        where.append("ransomware_use='Known'")
    if q:
        where.append("(cve LIKE ? OR vendor LIKE ? OR product LIKE ? OR name LIKE ?)")
        params += [f"%{q}%"] * 4
    rows = db.rows(conn, f"""SELECT cve, vendor, product, name, date_added, due_date, ransomware_use, epss,
                               epss_percentile, cvss, severity, cwes, priority, priority_parts
                             FROM vulnerabilities WHERE {' AND '.join(where)}
                             ORDER BY priority DESC, date_added DESC LIMIT ?""", (*params, limit))
    for r in rows:
        r["priority_parts"] = db.jload(r["priority_parts"], {})
        r["cwes"] = db.jload(r["cwes"])
    return rows


def new_kevs(conn, days: int) -> list[dict]:
    return db.rows(conn, """SELECT cve, vendor, product, name, date_added, ransomware_use, priority FROM vulnerabilities
                            WHERE date_added > date(?, ?) ORDER BY date_added DESC, priority DESC""",
                   (anchor(conn, "kev"), f"-{days} day"))


def top_indicators(conn, limit: int = 15) -> list[dict]:
    rows = db.rows(conn, """SELECT type, value, confidence, sources, malware, country, last_seen FROM indicators
                            WHERE context_only=0 AND type IN ('ip','url','domain','hash')
                            ORDER BY confidence DESC, last_seen DESC LIMIT ?""", (limit,))
    for r in rows:
        r["sources"] = db.jload(r["sources"])
    return rows


# ------------------------------------------------------------------ ransomware

def ransomware_groups(conn, limit: int = 40) -> list[dict]:
    a = anchor(conn)
    rows = db.rows(conn, """
        SELECT COALESCE(v.actor_id, 'group:' || v.group_name) AS actor_id,
               COALESCE(a.name, v.group_name) AS name, a.attack_id,
               SUM(v.discovered > date(:a,'-7 day')) AS d7,
               SUM(v.discovered > date(:a,'-30 day')) AS d30,
               COUNT(*) AS total, MAX(v.discovered) AS last_post
        FROM victims v LEFT JOIN actors a ON a.id = v.actor_id
        GROUP BY 1 ORDER BY d30 DESC, d7 DESC LIMIT :lim""", {"a": a, "lim": limit})
    for r in rows:
        r["top_sectors"] = [x["sector"] for x in db.rows(conn, """SELECT sector, COUNT(*) n FROM victims WHERE COALESCE(actor_id, 'group:' || group_name)=?
            AND sector NOT IN ('Not Found','') GROUP BY sector ORDER BY n DESC LIMIT 3""", (r["actor_id"],))]
        r["top_countries"] = [x["country"] for x in db.rows(conn, """SELECT country, COUNT(*) n FROM victims WHERE COALESCE(actor_id, 'group:' || group_name)=?
            AND country != '' GROUP BY country ORDER BY n DESC LIMIT 3""", (r["actor_id"],))]
    return rows


def victims_timeline(conn, days: int = 60) -> list[dict]:
    return db.rows(conn, """SELECT substr(discovered,1,10) AS day, COUNT(*) AS n FROM victims
                            WHERE discovered > date(?, ?) GROUP BY day ORDER BY day""", (anchor(conn), f"-{days} day"))


def victim_breakdown(conn, field: str, days: int = 30, limit: int = 12) -> list[dict]:
    assert field in ("sector", "country")
    return db.rows(conn, f"""SELECT {field} AS label, COUNT(*) AS value FROM victims
                             WHERE discovered > date(?, ?) AND {field} NOT IN ('', 'Not Found')
                             GROUP BY {field} ORDER BY value DESC LIMIT ?""", (anchor(conn), f"-{days} day", limit))


def recent_victims(conn, limit: int = 50, group: str = "") -> list[dict]:
    if group:
        return db.rows(conn, """SELECT v.discovered, v.group_name, a.name AS actor, v.victim, v.sector, v.country
                                FROM victims v LEFT JOIN actors a ON a.id=v.actor_id
                                WHERE v.actor_id=? OR v.group_name=? ORDER BY discovered DESC LIMIT ?""", (group, group, limit))
    return db.rows(conn, """SELECT v.discovered, v.group_name, a.name AS actor, v.victim, v.sector, v.country
                            FROM victims v LEFT JOIN actors a ON a.id=v.actor_id ORDER BY discovered DESC LIMIT ?""", (limit,))


# ------------------------------------------------------------------ infrastructure

def c2_by_family(conn, days: int | None = None) -> list[dict]:
    where = "type='ip' AND tags LIKE '%\"c2\"%' AND malware IS NOT NULL"
    params = ()
    if days:
        where += " AND first_seen >= ?"
        params = (db.now() - days * 86400,)
    return db.rows(conn, f"""SELECT malware AS family, COUNT(*) AS c2_ips, MAX(last_seen) AS last_seen,
                               GROUP_CONCAT(DISTINCT country) AS countries, GROUP_CONCAT(DISTINCT asn) AS asns
                             FROM indicators WHERE {where} GROUP BY malware ORDER BY c2_ips DESC""", params)


def c2_list(conn, limit: int = 100) -> list[dict]:
    return db.rows(conn, """SELECT value AS ip, malware, asn, as_name, country, confidence, sources, first_seen, last_seen
                            FROM indicators WHERE type='ip' AND tags LIKE '%"c2"%' ORDER BY last_seen DESC LIMIT ?""", (limit,))


def clusters(conn, kind: str = "", limit: int = 60) -> list[dict]:
    sql = "SELECT kind, key, size, members, families FROM clusters"
    params: tuple = ()
    if kind:
        sql += " WHERE kind=?"
        params = (kind,)
    rows = db.rows(conn, sql + " ORDER BY size DESC LIMIT ?", (*params, limit))
    for r in rows:
        r["members"] = db.jload(r["members"])[:12]
        r["families"] = db.jload(r["families"])
    return rows


def drop_overlaps(conn) -> list[dict]:
    return db.rows(conn, """SELECT i.value AS ip, r.dst AS netblock, i.sources, i.malware, i.confidence
                            FROM relationships r JOIN indicators i ON i.type='ip' AND r.src = 'ip:' || i.value
                            WHERE r.rel='inside' AND r.source='correlate' ORDER BY i.confidence DESC LIMIT 200""")


def phishing_stats(conn, limit: int = 15) -> dict:
    brands, tlds, hosting, domains = Counter(), Counter(), Counter(), Counter()
    rows = conn.execute("SELECT value, tags, host, reg_domain FROM indicators WHERE type='url' AND tags LIKE '%\"phishing\"%'").fetchall()
    for r in rows:
        tags = db.jload(r["tags"])
        brands.update(t.split(":", 1)[1] for t in tags if t.startswith("brand:"))
        hosting.update(t.split(":", 1)[1] for t in tags if t.startswith("hosting:"))
        host = (r["host"] or "").replace("[.]", ".")
        if host and not host[0].isdigit():
            tlds[host.rsplit(".", 1)[-1]] += 1
        elif host:
            tlds["(ip address)"] += 1
        if r["reg_domain"]:
            domains[r["reg_domain"]] += 1
    as_rows = lambda c: [{"label": k, "value": v} for k, v in c.most_common(limit)]
    return {"total": len(rows), "brands": as_rows(brands), "tlds": as_rows(tlds), "hosting": as_rows(hosting),
            "registered_domains": as_rows(domains),
            "unbranded": len(rows) - sum(1 for r in rows if "brand:" in (r["tags"] or ""))}


# ------------------------------------------------------------------ ATT&CK

def active_actor_ids(conn, days: int = 30) -> list[str]:
    return [r[0] for r in conn.execute("""SELECT DISTINCT actor_id FROM victims WHERE actor_id IS NOT NULL
                                          AND discovered > date(?, ?)""", (anchor(conn), f"-{days} day"))]


def technique_frequency(conn, scope: str = "active", limit: int = 30) -> dict:
    """How many tracked actors use each technique. scope: active (victims in 30 days) | all."""
    if scope == "active":
        actors = active_actor_ids(conn)
    else:
        actors = [r[0] for r in conn.execute("SELECT id FROM actors")]
    if not actors:
        return {"actors": 0, "techniques": [], "heatmap": {"rows": [], "cols": [], "matrix": []}}
    ph = ",".join("?" * len(actors))
    rows = db.rows(conn, f"""SELECT r.dst AS node, COUNT(DISTINCT r.src) AS actors FROM relationships r
                             WHERE r.source='correlate' AND r.rel='uses' AND r.dst LIKE 'technique:%' AND r.src IN ({ph})
                             GROUP BY r.dst ORDER BY actors DESC""", actors)
    tech = {t["id"]: t for t in db.rows(conn, "SELECT id, name, tactics FROM techniques")}
    out = []
    for r in rows:
        tid = r["node"].split(":", 1)[1]
        t = tech.get(tid, {})
        out.append({"id": tid, "name": t.get("name", "?"), "tactics": db.jload(t.get("tactics")), "actors": r["actors"]})
    # tactic x technique heatmap (parent techniques, top N per tactic)
    tactics = db.rows(conn, "SELECT id, shortname, name FROM tactics ORDER BY ord")
    parent_counts: dict[str, Counter] = defaultdict(Counter)
    for t in out:
        for short in t["tactics"]:
            parent_counts[short][t["id"].split(".")[0]] += t["actors"]
    cols = 12
    matrix, row_labels, cells = [], [], []
    for ta in tactics:
        top = parent_counts[ta["shortname"]].most_common(cols)
        row_labels.append(ta["id"])
        matrix.append([c for _, c in top] + [0] * (cols - len(top)))
        cells.append([tid for tid, _ in top])
    return {"actors": len(actors), "scope": scope, "techniques": out[:limit],
            "heatmap": {"rows": row_labels, "row_names": [t["name"] for t in tactics],
                        "cols": [f"#{i + 1}" for i in range(cols)], "matrix": matrix, "cells": cells}}


# ------------------------------------------------------------------ feeds / overview

def overview(conn) -> dict:
    feeds = collectors.feed_status(conn)
    health = []
    for f in feeds:
        last = f["last_run"] or {}
        health.append({"feed": f["feed"], "enabled": f["enabled"], "status": last.get("status", "never"),
                       "rows": last.get("rows"), "when": last.get("ended") or last.get("started"),
                       "mode": last.get("mode"), "error": (last.get("error") or "")[:160]})
    return {
        "counts": counts(conn),
        "feeds": health,
        "top_vulns": top_vulns(conn, 8),
        "top_indicators": top_indicators(conn, 8),
        "top_groups": ransomware_groups(conn, 8),
        "last_correlate": db.get_meta(conn, "last_correlate"),
        "formulas": {"indicator": scoring.INDICATOR_FORMULA, "vulnerability": scoring.VULN_FORMULA},
        "generated": timeutil.iso(db.now()),
        "anchor": {"victims": anchor(conn), "kev": anchor(conn, "kev")},
    }


def recent_runs(conn, feed: str = "", limit: int = 50) -> list[dict]:
    if feed:
        return db.rows(conn, "SELECT * FROM feed_runs WHERE feed=? ORDER BY id DESC LIMIT ?", (feed, limit))
    return db.rows(conn, "SELECT * FROM feed_runs ORDER BY id DESC LIMIT ?", (limit,))


def dumps(obj) -> str:
    return json.dumps(obj, default=str)
