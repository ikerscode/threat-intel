"""HTTP API smoke tests with FastAPI's TestClient (seeded fixture DB, no network)."""
import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client(seeded):
    from threatintel.server import app
    with TestClient(app) as c:
        yield c


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok", "name": "threat-intel", "version": "0.1.0"}


def test_overview_and_views(client):
    ov = client.get("/api/overview").json()
    assert ov["counts"]["vulnerabilities"] > 0 and ov["feeds"]
    assert client.get("/api/vulns?ransomware=true").json()["rows"]
    assert client.get("/api/ransomware").json()["groups"]
    assert client.get("/api/infrastructure").json()["clusters"]
    assert client.get("/api/attack?scope=all").json()["techniques"]
    assert client.get("/").status_code == 200


def test_search_and_enrich(client):
    r = client.get("/api/search", params={"q": "akira"}).json()
    assert r["found"] and r["graph"]["nodes"]
    e = client.post("/api/enrich", json={"text": "8.8.8.8\nbad[.]example"}).json()
    assert e["count"] == 2
    assert client.post("/api/enrich", json={}).status_code == 400


def test_feed_toggle_and_refresh_job(client):
    assert client.post("/api/feeds/tor/enable", json={"enabled": False}).json()["enabled"] is False
    assert client.post("/api/feeds/tor/enable", json={"enabled": None}).json()["enabled"] is True
    job = client.post("/api/feeds/urlhaus/refresh").json()  # no key -> skipped, no network
    for _ in range(50):
        j = client.get(f"/api/jobs/{job['id']}").json()
        if j["status"] != "running":
            break
        time.sleep(0.1)
    assert j["result"]["status"] == "skipped"


def test_exports_and_reports(client):
    assert client.get("/api/export/stix").json()["type"] == "bundle"
    assert client.get("/api/export/blocklist/ip").text.startswith("# seclab")
    assert client.get("/api/export/blocklist/nope").status_code == 404
    rep = client.post("/api/reports?days=7").json()
    assert client.get(f"/api/reports/{rep['name']}.html").status_code == 200
