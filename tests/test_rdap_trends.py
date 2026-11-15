"""RDAP lookups (mock transport serving real captured answers) and history/trends."""
import time
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

from conftest import rdap_mock_transport
from threatintel import db, rdap, trends

HOST = {"host": "127.0.0.1"}


@pytest.fixture(scope="module")
def client(seeded):
    from threatintel.server import app
    with TestClient(app) as c:
        yield c


def test_target_uses_registered_domain_and_skips_private():
    assert rdap.target("hxxps://login.secure.evil[.]example.co.uk/x") == ("domain", "example.co.uk")
    assert rdap.target("8.8.8.8") == ("ip", "8.8.8.8")
    assert rdap.target("10.1.2.3") is None and rdap.target("CVE-2024-1") is None


def test_domain_and_ip_lookup_only_contact_registries(conn, monkeypatch):
    log = []
    monkeypatch.setattr(rdap, "TRANSPORT", rdap_mock_transport(log))
    d = rdap.lookup(conn, "www.example.com", refresh=True)
    assert d["status"] == "ok" and d["registered"].startswith("1995-08-14") and d["registrar"]
    ip = rdap.lookup(conn, "8.8.8.8", refresh=True)
    assert ip["status"] == "ok" and "GOGL" in ip["network"]
    hosts = {urlsplit(u).hostname for u in log}
    assert hosts <= {"data.iana.org", "rdap.verisign.com", "rdap.arin.net"}
    assert "www.example.com" not in hosts and "8.8.8.8" not in hosts


def test_not_found_is_cached(conn, monkeypatch):
    log = []
    monkeypatch.setattr(rdap, "TRANSPORT", rdap_mock_transport(log))
    r = rdap.lookup(conn, "no-such-name-0001.com", refresh=True)
    assert r["status"] == "not-found"
    n = len(log)
    assert rdap.lookup(conn, "no-such-name-0001.com")["status"] == "not-found" and len(log) == n


def test_api_rdap_search_and_enrich(client):
    r = client.get("/api/rdap", params={"q": "example.com"}, headers=HOST).json()
    assert r["rdap"]["status"] == "ok"
    s = client.get("/api/search", params={"q": "example.com", "rdap": "true"}, headers=HOST).json()
    assert s["rdap"]["registrar"]
    e = client.post("/api/enrich?rdap=true", json={"iocs": ["example.com", "8.8.8.8"]}, headers=HOST).json()
    assert all("rdap" in x for x in e["results"])
    assert client.get("/api/rdap", params={"q": "192.168.1.1"}, headers=HOST).status_code == 400


def test_enrich_contract_unchanged(client):
    e = client.post("/api/enrich", json={"iocs": ["8.8.8.8"]}, headers=HOST).json()
    r = e["results"][0]
    for k in ("input", "type", "value", "match", "verdict", "asn", "inside_drop"):
        assert k in r
    assert set(e) >= {"count", "summary", "results"}


def test_snapshot_and_trends(client, conn):
    assert conn.execute("SELECT COUNT(*) FROM daily_snapshot").fetchone()[0] > 0
    t = client.get("/api/trends?days=30", headers=HOST).json()
    for k in ("daily", "new_c2_by_family", "c2_reported_by_family", "phishing_by_brand", "phishing_by_tld",
              "victims_by_week", "baseline_day", "history_days"):
        assert k in t
    assert t["daily"] and t["daily"][0]["indicators"]
    assert t["victims_by_week"]


def test_trends_count_new_per_day(isolated_env):
    c = db.connect(isolated_env / "trend.db")
    now = time.time()
    db.upsert_indicator(c, type="ip", value="45.9.168.1", source="feodo", tags=["c2"], malware="qakbot",
                        first_seen=now - 86400, observed_at=now - 86400)
    db.upsert_indicator(c, type="ip", value="45.9.168.2", source="feodo", tags=["c2"], malware="qakbot",
                        first_seen=now, observed_at=now)
    rows = trends.new_c2_by_family(c, 7)
    assert sum(r["n"] for r in rows) == 2 and len({r["day"] for r in rows}) == 2
    trends.snapshot(c)
    assert trends.snapshots(c, 7)[0]["c2_ips"] == 2
    c.close()


def test_phishing_and_trends_endpoints(client):
    p = client.get("/api/phishing?limit=5", headers=HOST).json()
    assert p["rows"] and "formula" in p and p["summary"]["total"] > 0
    inf = client.get("/api/infrastructure", headers=HOST).json()
    assert inf["by_source"] and "misp_events" in inf and inf["c2_by_family"] is not None
