"""The dashboard must refuse DNS-rebinding and cross-site requests and send a strict CSP."""
from fastapi.testclient import TestClient

import threatintel.server as server


def client():
    app = server.app if hasattr(server, "app") else server.create_app()
    return TestClient(app)


def test_rejects_foreign_host():
    r = client().get("/api/health", headers={"host": "evil.example:8000"})
    assert r.status_code == 403


def test_rejects_cross_site_post():
    r = client().post("/api/health", headers={"host": "127.0.0.1", "sec-fetch-site": "cross-site"})
    assert r.status_code == 403
    r = client().post("/api/health", headers={"host": "127.0.0.1", "origin": "https://evil.example"})
    assert r.status_code == 403


def test_local_request_has_security_headers():
    r = client().get("/api/health", headers={"host": "127.0.0.1:8000"})
    assert r.status_code == 200
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
