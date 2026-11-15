"""Intelligence brief generator (Markdown + standalone HTML).

Both outputs are rendered from the same section data so they always agree.
All indicator values are already defanged in the database.
"""
from __future__ import annotations

import html
from pathlib import Path

from . import config, db, queries, scoring, timeutil, trends


def _sections(conn, days: int) -> list[dict]:
    """Each section: {title, intro, columns, rows} or {title, text}."""
    c = queries.counts(conn)
    sections = [{
        "title": "Summary",
        "text": (f"Tracking {c['indicators']} malicious indicators ({c['c2_ips']} C2 IPs, {c['phishing_urls']} phishing URLs), "
                 f"{c['drop_netblocks']} DROP netblocks, {c['vulnerabilities']} known exploited vulnerabilities "
                 f"({c['kev_ransomware']} with known ransomware use), {c['actors']} actors "
                 f"({c['merged_actors']} merged across ATT&CK and ransomware.live) and {c['victims']} ransomware leak-site posts. "
                 f"Also {c['c2_certs']} C2 TLS certificates, {c['reputation_ips']} attacker/reputation IPs, "
                 f"{c['phishing_domains']} phishing domains and {c['misp_events']} MISP OSINT events."),
    }]
    kevs = queries.new_kevs(conn, days)
    sections.append({
        "title": f"New KEV entries ({days} days to {queries.anchor(conn, 'kev')})",
        "intro": "" if kevs else "No CVEs were added to the CISA KEV catalogue in this window.",
        "columns": ["cve", "vendor", "product", "date_added", "ransomware_use", "priority"],
        "rows": kevs[:25],
    })
    top = queries.top_vulns(conn, 12)
    for v in top:
        p = v["priority_parts"]
        v["breakdown"] = (f"KEV {p.get('kev', 0):.0f} + EPSS {p.get('epss', 0):.1f} + CVSS {p.get('cvss', 0):.1f}"
                          f"{'*' if p.get('cvss_assumed') else ''} + RW {p.get('ransomware', 0):.0f} + recency {p.get('recency', 0):.1f}")
        v["epss"] = f"{v['epss']:.3f}" if v["epss"] is not None else "-"
    sections.append({
        "title": "Top-priority vulnerabilities",
        "intro": f"Formula: {scoring.VULN_FORMULA}. (* CVSS assumed 7.0 where NVD data is missing.)",
        "columns": ["cve", "vendor", "product", "priority", "epss", "cvss", "ransomware_use", "breakdown"],
        "rows": top,
    })
    groups = queries.ransomware_groups(conn, 12)
    for g in groups:
        g["sectors"] = ", ".join(g["top_sectors"])
        g["countries"] = ", ".join(g["top_countries"])
    sections.append({
        "title": "Most active ransomware groups",
        "intro": (f"7/30-day windows end {queries.anchor(conn)}. Counts are leak-site posts collected by ransomware.live; "
                  "they are claims made by the criminals and are not verified."),
        "columns": ["name", "attack_id", "d7", "d30", "sectors", "countries", "last_post"],
        "rows": groups,
    })
    sectors = queries.victim_breakdown(conn, "sector", 30, 8)
    countries = queries.victim_breakdown(conn, "country", 30, 8)
    sections.append({
        "title": "Victim sectors and countries (30 days)",
        "text": ("Sectors: " + ", ".join(f"{s['label']} ({s['value']})" for s in sectors) + ". "
                 "Countries: " + ", ".join(f"{s['label']} ({s['value']})" for s in countries) + "."),
    })
    fresh = queries.c2_by_family(conn, days)
    sections.append({
        "title": f"New C2 infrastructure by malware family (first seen in last {days} days)",
        "intro": "" if fresh else "No new C2 servers were first seen in this window; current totals are shown instead.",
        "columns": ["family", "c2_ips", "countries", "asns"],
        "rows": fresh or queries.c2_by_family(conn),
    })
    reported = trends.new_c2_by_family(conn, days, "reported")
    sections.append({
        "title": f"C2 listings per day by family (feed-reported dates, last {days} days)",
        "intro": ("From the dates the feeds publish (SSLBL certificate listing date, Feodo/ThreatFox first seen). "
                  "" if reported else "No dated C2 listings in this window."),
        "columns": ["day", "family", "n"],
        "rows": reported[:30],
    })
    src = queries.infrastructure_by_source(conn, days)
    listed = {k[len("listed:"):]: v for k, v in ((r["k"], db.jload(r["v"], {})) for r in
              db.rows(conn, "SELECT k, v FROM meta WHERE k LIKE 'listed:%'"))}
    for r in src:
        l = listed.get(r["source"])
        r["sampled"] = f"{l['kept']} of {l['listed']}" if l else ""
    sections.append({
        "title": "Malicious infrastructure by source",
        "intro": (f"new_observed = first seen by this lab in the last {days} days. Large rotating lists are a stable "
                  "hash sample (sampled column). malicious_verdicts = confidence >= 60, which single reputation lists "
                  "cannot reach alone."),
        "columns": ["source", "indicators", "new_observed", "avg_confidence", "malicious_verdicts", "sampled"],
        "rows": src,
    })
    ph = queries.phishing_stats(conn, 8)
    an = ph["analysis"]
    fmt = lambda xs: ", ".join(f"{x['label']} ({x['value']})" for x in xs) or "none"
    per = "; ".join(f"{k}: {v['total']} total, unbranded {v['unbranded']} ({v['unbranded_pct']}%) now vs "
                    f"{v['unbranded_keyword_only']} ({v['unbranded_pct_keyword_only']}%) with keywords only"
                    for k, v in an["by_source"].items())
    sections.append({
        "title": "Phishing trends",
        "text": (f"{ph['total']} phishing URLs and {an['by_type'].get('domain', {}).get('total', 0)} phishing domains analysed "
                 f"offline. Brand matching now uses tokens, edit distance and homoglyph folding. {(per + '.') if per else 'No phishing data.'} "
                 f"Detection methods: {fmt(an['methods'])}. Top impersonated brands: {fmt(an['brands'][:8])}. "
                 f"Top TLDs: {fmt(an['tlds'][:8])}. Hosting platforms: {fmt(ph['hosting'])}. "
                 f"Score bands: {fmt(an['score_bands'])}."),
    })
    top_ph = queries.phishing_top(conn, 12, min_score=40)
    sections.append({
        "title": "Highest-scoring brand impersonation",
        "intro": f"Formula: {scoring.PHISH_FORMULA}. Values are defanged.",
        "columns": ["value", "brand", "method", "score", "why"],
        "rows": top_ph,
    })
    daily = trends.daily_table(conn, max(days, 14))
    sections.append({
        "title": "Daily history",
        "intro": ("One row per day with a correlation snapshot. new_indicators / new_c2 count first observations by this "
                  "lab; the baseline day (first collection) counts everything already listed."),
        "columns": ["day", "baseline", "indicators", "c2_ips", "c2_certs", "phishing_urls", "phishing_domains",
                    "new_indicators", "new_c2", "victims"],
        "rows": daily,
    })
    weekly = trends.victims_by_week(conn, 6, 6)
    sections.append({
        "title": "Ransomware leak-site posts per week (busiest groups)",
        "columns": ["week", "group", "n"],
        "rows": weekly[:36],
    })
    events = queries.misp_events(conn, 10)
    for e in events:
        e["actors"] = ", ".join(a.split(":", 1)[1] for a in e["actors"])
        e["malware"] = ", ".join(e["malware"])
    sections.append({
        "title": "Recent MISP OSINT events (CIRCL)",
        "intro": "" if events else "No MISP events collected.",
        "columns": ["date", "org", "info", "stored", "actors", "malware"],
        "rows": events,
    })
    tf = queries.technique_frequency(conn, "active", 15)
    sections.append({
        "title": "ATT&CK techniques most associated with active groups",
        "intro": f"Across {tf['actors']} actors with leak-site posts in the last 30 days, using ATT&CK and ransomware.live TTP mappings.",
        "columns": ["id", "name", "actors"],
        "rows": tf["techniques"],
    })
    feeds = queries.overview(conn)["feeds"]
    for f in feeds:
        f["when"] = timeutil.iso(f["when"]) if f["when"] else ""
    sections.append({
        "title": "Collection status",
        "columns": ["feed", "status", "mode", "rows", "when"],
        "rows": feeds,
    })
    return sections


def _cell(v) -> str:
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v:.1f}"
    return str(v).replace("|", "/").replace("\n", " ")


def to_markdown(title: str, sections: list[dict]) -> str:
    out = [f"# {title}", ""]
    for s in sections:
        out += [f"## {s['title']}", ""]
        if s.get("text"):
            out += [s["text"], ""]
        if s.get("intro"):
            out += [s["intro"], ""]
        if s.get("rows"):
            cols = s["columns"]
            out.append("| " + " | ".join(cols) + " |")
            out.append("|" + "---|" * len(cols))
            for r in s["rows"]:
                out.append("| " + " | ".join(_cell(r.get(c)) for c in cols) + " |")
            out.append("")
    return "\n".join(out)


CSS = """body{background:#0b0b0d;color:#dcd8cc;font:14px/1.5 "DejaVu Sans Mono",monospace;max-width:1100px;margin:24px auto;padding:0 16px}
h1{letter-spacing:.1em;text-transform:uppercase;font-size:20px;border-bottom:1px solid #b8322a;padding-bottom:8px}
h2{font-size:13px;letter-spacing:.14em;text-transform:uppercase;color:#8b877d;border-bottom:1px dashed #2b2a31;margin-top:28px}
table{width:100%;border-collapse:collapse;font-size:12.5px}th,td{text-align:left;padding:4px 8px;border-bottom:1px solid #24232a}
th{color:#8b877d;font-weight:normal;text-transform:uppercase;font-size:11px}p.muted{color:#8b877d}"""


def to_html(title: str, sections: list[dict]) -> str:
    e = html.escape
    parts = [f"<!doctype html><html><head><meta charset='utf-8'><title>{e(title)}</title><style>{CSS}</style></head><body>",
             f"<h1>{e(title)}</h1>"]
    for s in sections:
        parts.append(f"<h2>{e(s['title'])}</h2>")
        if s.get("text"):
            parts.append(f"<p>{e(s['text'])}</p>")
        if s.get("intro"):
            parts.append(f"<p class='muted'>{e(s['intro'])}</p>")
        if s.get("rows"):
            parts.append("<table><thead><tr>" + "".join(f"<th>{e(c)}</th>" for c in s["columns"]) + "</tr></thead><tbody>")
            for r in s["rows"]:
                parts.append("<tr>" + "".join(f"<td>{e(_cell(r.get(c)))}</td>" for c in s["columns"]) + "</tr>")
            parts.append("</tbody></table>")
    parts.append("</body></html>")
    return "\n".join(parts)


def generate(conn, days: int = 7) -> dict:
    stamp = timeutil.iso(db.now())
    title = f"Threat intelligence brief {stamp[:10]} (last {days} days)"
    sections = _sections(conn, days)
    out_dir = config.get().reports_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    base = "brief-" + stamp.replace(":", "").replace("-", "")[:15]
    md_path, html_path = out_dir / f"{base}.md", out_dir / f"{base}.html"
    md_path.write_text(to_markdown(title, sections), encoding="utf-8")
    html_path.write_text(to_html(title, sections), encoding="utf-8")
    return {"name": base, "md_path": str(md_path), "html_path": str(html_path), "title": title}


def list_reports() -> list[dict]:
    d = config.get().reports_dir
    if not d.exists():
        return []
    out = []
    for p in sorted(d.glob("brief-*.md"), reverse=True):
        out.append({"name": p.stem, "size": p.stat().st_size, "modified": p.stat().st_mtime,
                    "has_html": p.with_suffix(".html").exists()})
    return out


def report_path(name: str, fmt: str) -> Path | None:
    if not name.startswith("brief-") or "/" in name or ".." in name or fmt not in ("md", "html"):
        return None
    p = config.get().reports_dir / f"{name}.{fmt}"
    return p if p.exists() else None
