"""History and trends.

Two kinds of history are kept:

- daily_snapshot: key counts written after every correlation run (the last run
  of a day wins). These survive pruning of rotating lists, so the "how many C2
  servers did we track on 3 November" question stays answerable.
- per-indicator observation history in `sightings` (first_obs, last_obs,
  days_seen per feed), maintained by db.upsert_indicator on every run.

"New per day" trends come in two flavours, and the API names them clearly:
- observed: the day this lab first saw the indicator in any feed (first_obs).
  The first collection day counts everything as new, so it is flagged as the
  baseline day.
- reported: the date the feed itself gives (Feodo first_seen, SSLBL listing
  date, ThreatFox first_seen). Gives real history from the first run, but only
  for feeds that publish dates.
"""
from __future__ import annotations

from . import db, timeutil

MALICIOUS_SOURCES_SQL = "s.source NOT IN ('enrich', 'tor')"


def snapshot(conn, day: str | None = None) -> dict:
    """Write today's key counts to daily_snapshot and return them."""
    from .queries import counts
    day = day or timeutil.iso_date(db.now())
    c = counts(conn)
    metrics = {k: v for k, v in c.items() if isinstance(v, (int, float))}
    for r in conn.execute("""SELECT s.source, COUNT(*) FROM sightings s GROUP BY s.source"""):
        metrics[f"source:{r[0]}"] = r[1]
    branded = conn.execute("""SELECT COUNT(*) FROM phishing_analysis pa JOIN indicators i ON i.id=pa.indicator_id
                              WHERE i.type='url' AND pa.brands != '[]'""").fetchone()[0]
    metrics["phishing_urls_branded"] = branded
    metrics["phishing_domains_branded"] = conn.execute(
        """SELECT COUNT(*) FROM phishing_analysis pa JOIN indicators i ON i.id=pa.indicator_id
           WHERE i.type='domain' AND pa.brands != '[]'""").fetchone()[0]
    metrics["c2_certs"] = conn.execute("SELECT COUNT(*) FROM indicators WHERE tags LIKE '%\"x509-sha1\"%'").fetchone()[0]
    metrics["new_observed_today"] = conn.execute(
        f"""SELECT COUNT(*) FROM (SELECT indicator_id, MIN(first_obs) f FROM sightings s WHERE {MALICIOUS_SOURCES_SQL}
            GROUP BY indicator_id) WHERE strftime('%Y-%m-%d', f, 'unixepoch') = ?""", (day,)).fetchone()[0]
    conn.executemany("INSERT OR REPLACE INTO daily_snapshot(day, metric, value) VALUES (?,?,?)",
                     [(day, k, v) for k, v in metrics.items()])
    return metrics


def snapshots(conn, days: int = 30) -> list[dict]:
    """One row per day: {day, metric: value, ...}."""
    rows: dict[str, dict] = {}
    for r in conn.execute("SELECT day, metric, value FROM daily_snapshot WHERE day > date('now', ?) ORDER BY day",
                          (f"-{days} day",)):
        v = r["value"]
        rows.setdefault(r["day"], {"day": r["day"]})[r["metric"]] = int(v) if isinstance(v, float) and v.is_integer() else v
    return list(rows.values())


def baseline_day(conn) -> str | None:
    r = conn.execute(f"SELECT MIN(first_obs) FROM sightings s WHERE {MALICIOUS_SOURCES_SQL}").fetchone()[0]
    return timeutil.iso_date(r) if r else None


def _first_obs_sql(where: str) -> str:
    return f"""SELECT i.id, i.type, i.value, i.malware, i.host, i.reg_domain, i.tags, MIN(s.first_obs) AS f
               FROM indicators i JOIN sightings s ON s.indicator_id=i.id
               WHERE {MALICIOUS_SOURCES_SQL} AND {where} GROUP BY i.id"""


def new_c2_by_family(conn, days: int = 30, basis: str = "observed") -> list[dict]:
    """[{day, family, n}] of C2 indicators (IPs tagged c2 and C2 certificates) first seen per day."""
    c2 = "(i.tags LIKE '%\"c2\"%' OR i.tags LIKE '%\"c2-certificate\"%')"
    if basis == "reported":
        sql = f"""SELECT strftime('%Y-%m-%d', i.first_seen, 'unixepoch') AS day, COALESCE(i.malware, '(unknown)') AS family,
                  COUNT(*) AS n FROM indicators i WHERE {c2} AND i.first_seen > CAST(strftime('%s','now', ?) AS REAL)
                  GROUP BY day, family ORDER BY day DESC, n DESC"""
        return db.rows(conn, sql, (f"-{days} day",))
    sql = f"""SELECT strftime('%Y-%m-%d', f, 'unixepoch') AS day, COALESCE(malware, '(unknown)') AS family, COUNT(*) AS n
              FROM ({_first_obs_sql(c2)}) WHERE f > CAST(strftime('%s','now', ?) AS REAL)
              GROUP BY day, family ORDER BY day DESC, n DESC"""
    return db.rows(conn, sql, (f"-{days} day",))


def phishing_by(conn, field: str, days: int = 30, limit_per_day: int = 8) -> list[dict]:
    """[{day, key, n}] of phishing URLs/domains first observed per day, by brand or TLD."""
    assert field in ("brand", "tld")
    rows = db.rows(conn, f"""SELECT x.f, x.type, pa.brands, pa.tld FROM ({_first_obs_sql("i.tags LIKE '%\"phishing\"%'")}) x
                             LEFT JOIN phishing_analysis pa ON pa.indicator_id = x.id
                             WHERE x.f > CAST(strftime('%s','now', ?) AS REAL)""", (f"-{days} day",))
    counts: dict[tuple, int] = {}
    for r in rows:
        day = timeutil.iso_date(r["f"])
        if field == "brand":
            keys = db.jload(r["brands"])[:1] or ["(no brand)"]
        else:
            keys = [r["tld"] or "(ip)"]
        for k in keys:
            counts[(day, k)] = counts.get((day, k), 0) + 1
    out = [{"day": d, "key": k, "n": n} for (d, k), n in counts.items()]
    out.sort(key=lambda r: (r["day"], -r["n"]), reverse=False)
    out.sort(key=lambda r: r["day"], reverse=True)
    trimmed, per_day = [], {}
    for r in out:
        per_day[r["day"]] = per_day.get(r["day"], 0) + 1
        if per_day[r["day"]] <= limit_per_day:
            trimmed.append(r)
    return trimmed


def victims_by_week(conn, weeks: int = 8, top: int = 8) -> list[dict]:
    """[{week, group, n}] of leak-site posts per ISO week for the busiest groups (anchored on the newest post)."""
    from .queries import anchor
    a = anchor(conn)
    rows = db.rows(conn, """SELECT strftime('%Y-W%W', v.discovered) AS week, COALESCE(ac.name, v.group_name) AS grp, COUNT(*) AS n
                            FROM victims v LEFT JOIN actors ac ON ac.id=v.actor_id
                            WHERE v.discovered > date(?, ?) GROUP BY week, grp""", (a, f"-{weeks * 7} day"))
    totals: dict[str, int] = {}
    for r in rows:
        totals[r["grp"]] = totals.get(r["grp"], 0) + r["n"]
    keep = set(sorted(totals, key=lambda g: -totals[g])[:top])
    out = [{"week": r["week"], "group": r["grp"], "n": r["n"]} for r in rows if r["grp"] in keep]
    return sorted(out, key=lambda r: (r["week"], -r["n"]), reverse=True)


def new_by_source(conn, days: int = 30) -> list[dict]:
    return db.rows(conn, f"""SELECT strftime('%Y-%m-%d', first_obs, 'unixepoch') AS day, source, COUNT(*) AS n
                             FROM sightings s WHERE {MALICIOUS_SOURCES_SQL} AND first_obs > CAST(strftime('%s','now', ?) AS REAL)
                             GROUP BY day, source ORDER BY day DESC, n DESC""", (f"-{days} day",))


def daily_table(conn, days: int = 14) -> list[dict]:
    """Compact per-day rows for the HUD tables and the terminal view."""
    snaps = {s["day"]: s for s in snapshots(conn, days)}
    new = {}
    for r in new_by_source(conn, days):
        new.setdefault(r["day"], 0)
        new[r["day"]] += r["n"]
    c2 = {}
    for r in new_c2_by_family(conn, days):
        c2[r["day"]] = c2.get(r["day"], 0) + r["n"]
    base = baseline_day(conn)
    out = []
    for day in sorted(set(snaps) | set(new), reverse=True):
        s = snaps.get(day, {})
        out.append({"day": day, "baseline": day == base,
                    "indicators": s.get("indicators"), "c2_ips": s.get("c2_ips"), "c2_certs": s.get("c2_certs"),
                    "phishing_urls": s.get("phishing_urls"), "phishing_domains": s.get("phishing_domains"),
                    "phishing_branded": (s.get("phishing_urls_branded") or 0) + (s.get("phishing_domains_branded") or 0)
                    if s else None,
                    "victims": s.get("victims"), "new_indicators": new.get(day, 0), "new_c2": c2.get(day, 0)})
    return out


def trends(conn, days: int = 30) -> dict:
    return {
        "days": days,
        "baseline_day": baseline_day(conn),
        "history_days": conn.execute("SELECT COUNT(DISTINCT day) FROM daily_snapshot").fetchone()[0],
        "daily": daily_table(conn, days),
        "snapshots": snapshots(conn, days),
        "new_c2_by_family": new_c2_by_family(conn, days, "observed"),
        "c2_reported_by_family": new_c2_by_family(conn, days, "reported"),
        "phishing_by_brand": phishing_by(conn, "brand", days),
        "phishing_by_tld": phishing_by(conn, "tld", days),
        "victims_by_week": victims_by_week(conn),
        "new_by_source": new_by_source(conn, days),
        "note": ("observed = first time this lab saw it (the baseline day counts everything already listed); "
                 "reported = the date the feed gives"),
    }
