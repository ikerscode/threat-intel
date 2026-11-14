"""Pivot search, enrichment, exports and the brief."""
import json

from threatintel import brief, db, enrich, export, pivot


def test_search_cve(conn):
    cve = conn.execute("SELECT cve FROM vulnerabilities WHERE ransomware_use='Known' ORDER BY priority DESC").fetchone()[0]
    res = pivot.search(conn, cve.lower())
    assert res["found"] and res["entity"]["cve"] == cve
    types = {n["type"] for n in res["graph"]["nodes"]}
    assert {"cve", "product"} <= types and "campaign" in types


def test_search_group_and_technique(conn):
    res = pivot.search(conn, "Akira")
    assert res["entity"]["id"] == "actor:akira" and res["linked"]["techniques"]
    assert res["linked"]["recent_victims"]
    t = pivot.search(conn, "T1486")
    assert t["found"] and any(a["id"] == "actor:akira" for a in t["linked"]["actors"])


def test_search_ip_and_graph_shape(conn):
    ip = conn.execute("SELECT value FROM indicators WHERE sources LIKE '%feodo%' LIMIT 1").fetchone()[0]
    res = pivot.search(conn, ip)
    ids = {n["id"] for n in res["graph"]["nodes"]}
    assert res["found"] and f"ip:{ip}" in ids
    assert all(l["source"] in ids and l["target"] in ids for l in res["graph"]["links"])


def test_search_unknown_gives_suggestions(conn):
    res = pivot.search(conn, "akir")
    assert not res["found"]


def test_enrich_list_and_stix(conn):
    ip = conn.execute("SELECT value FROM indicators WHERE sources LIKE '%threatfox%' AND type='ip' ORDER BY confidence DESC").fetchone()[0]
    res = enrich.enrich(conn, [ip, "8.8.8.8", "hxxp://nothing[.]example/a"])
    by = {r["input"]: r for r in res["results"]}
    assert by[ip]["match"] and by[ip]["verdict"] in ("malicious", "suspicious") and by[ip]["malware"]
    assert by["8.8.8.8"]["verdict"] == "unknown"
    bundle = {"type": "bundle", "id": "bundle--1", "objects": [
        {"type": "indicator", "pattern": f"[ipv4-addr:value = '{ip}']"},
        {"type": "domain-name", "value": "update-qakbot.example"}]}
    items = enrich.parse_payload(bundle)
    assert items == [ip, "update-qakbot.example"]
    res2 = enrich.enrich(conn, items)
    assert all(r["match"] for r in res2["results"])


def test_stix_bundle_and_blocklists(conn):
    b = export.stix_bundle(conn, min_confidence=40)
    ids = [o["id"] for o in b["objects"]]
    assert len(ids) == len(set(ids))
    inds = [o for o in b["objects"] if o["type"] == "indicator"]
    assert inds and all(o["pattern"].startswith("[") and o["spec_version"] == "2.1" for o in inds)
    assert any(o["type"] == "relationship" and o["relationship_type"] == "indicates" for o in b["objects"])
    assert "[.]" not in json.dumps([o["pattern"] for o in inds])  # machine format is fanged
    urls = export.blocklist(conn, "url", 0)
    assert "DEFANGED" in urls and "hxxp" in urls
    assert "http://" in export.blocklist(conn, "url", 0, fanged=True)


def test_brief(conn):
    out = brief.generate(conn, days=7)
    md = open(out["md_path"]).read()
    for heading in ("Top-priority vulnerabilities", "Most active ransomware groups", "Phishing trends",
                    "ATT&CK techniques most associated with active groups", "New C2 infrastructure"):
        assert heading in md
    assert "<table>" in open(out["html_path"]).read()
    assert brief.report_path(out["name"], "md") and brief.report_path("../etc/passwd", "md") is None
