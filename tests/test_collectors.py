"""Each collector's normalise() against its bundled fixture (no network)."""
import json

from threatintel import collectors
from threatintel.config import FIXTURES


def norm(name):
    c = collectors.get(name)
    return c.normalise(c.load_fixture(FIXTURES))


def test_kev():
    rows = norm("kev")
    assert len(rows) > 100
    assert all(r["cve"].startswith("CVE-") for r in rows)
    assert any(r["ransomware_use"] == "Known" for r in rows)


def test_epss_and_nvd():
    epss = norm("epss")
    assert epss and all(0 <= r["epss"] <= 1 for r in epss)
    nvd = norm("nvd")
    assert any(r["cvss"] and r["cvss"]["score"] for r in nvd)
    assert any(r["cwes"] for r in nvd)


def test_attack():
    rec = norm("attack")
    assert len(rec["tactics"]) >= 12
    assert any(t["id"] == "T1486" for t in rec["techniques"])
    assert any(g["id"] == "G1024" for g in rec["groups"])  # Akira
    assert any(r["rel"] == "uses" and r["src"].startswith("attack-group:") for r in rec["relationships"])


def test_feodo():
    rows = norm("feodo")
    assert rows and all(r["malware"] for r in rows)
    assert {"qakbot", "emotet"} & {r["malware"] for r in rows}


def test_openphish_is_defanged():
    rows = norm("openphish")
    assert len(rows) >= 100
    assert all(r["url"].startswith("hxxp") and "[.]" in r["url"] for r in rows)


def test_ransomware_drops_onion_addresses():
    rec = norm("ransomware")
    assert rec["groups"] and rec["victims"]
    blob = json.dumps(rec)
    assert ".onion" not in blob
    assert any(g["techniques"] for g in rec["groups"])


def test_spamhaus_tor_threatfox_urlhaus():
    drop = norm("spamhaus")
    assert drop and all("/" in r["cidr"] for r in drop)
    tor = norm("tor")
    assert len(tor) >= 100
    tf = norm("threatfox")
    ips = [r for r in tf if r["type"] == "ip"]
    assert ips and all(":" not in r["value"] for r in ips) and all(r["port"] for r in ips)
    uh = norm("urlhaus")
    assert uh and all(r["url"].startswith("hxxp") for r in uh)
    assert "synthetic" not in {r["malware"] for r in uh}


def test_key_required_feed_skips_without_key(conn, monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    r = collectors.run_feed("threatfox", conn=conn)
    assert r["status"] == "skipped" and "ABUSECH_AUTH_KEY" in r["error"]
