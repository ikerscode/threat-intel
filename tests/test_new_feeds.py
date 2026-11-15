"""Collectors added in the second round: parsers against their fixtures, caps, safety, pruning."""
import json

import httpx
import pytest

from threatintel import collectors, db, fetch
from threatintel.collectors.base import stable_sample
from threatintel.collectors.circl import attribute_iocs, strip_attachments, tag_links
from threatintel.config import FIXTURES


def norm(name):
    c = collectors.get(name)
    return c, c.normalise(c.load_fixture(FIXTURES))


@pytest.mark.parametrize("name", ["et_compromised", "cins", "blocklistde"])
def test_ip_lists_parse_and_skip_private(name):
    c, rows = norm(name)
    assert len(rows) >= 50
    assert all(not r["ip"].startswith(("10.", "192.168.", "127.")) for r in rows)
    assert c.normalise("# comment\n10.0.0.1\n8.8.8.8 # inline\nnot-an-ip\n") == [{"ip": "8.8.8.8"}]


def test_stable_sample_is_deterministic_and_capped():
    vals = [f"198.51.100.{i}" for i in range(200)]
    a, b = stable_sample(vals, 50), stable_sample(list(reversed(vals)), 50)
    assert len(a) == 50 and set(a) == set(b)
    # an item kept today stays kept when unrelated items join the list
    assert set(a) - set(stable_sample(vals + [f"203.0.113.{i}" for i in range(5)], 55)) <= set(a)


def test_sslbl_certificates():
    _, rows = norm("sslbl")
    assert rows and all(len(r["sha1"]) == 40 for r in rows)
    assert any(r["malware"] for r in rows)
    assert all(r["listed"] for r in rows)
    assert rows == sorted(rows, key=lambda r: r["listed"], reverse=True)


def test_phishing_army_defanged_fixture_and_test_domain_dropped():
    c, rows = norm("phishing_army")
    assert len(rows) >= 100
    assert all("[" not in r["host"] for r in rows)
    assert c.normalise("amiprotected.it\nwww.amiprotected.it\nlogin-paypa1[.]example\n") == [
        {"host": "login-paypa1.example", "reg_domain": "login-paypa1.example"}]


def test_circl_events_and_links():
    _, rec = norm("circl")
    events = rec["events"]
    assert events and all(e["uuid"] for e in events)
    assert sum(len(e["iocs"]) for e in events) > 20
    blob = json.dumps(events)
    assert '"data"' not in blob
    for e in events:
        for i in e["iocs"]:
            if i["type"] in ("url", "domain"):
                assert "[.]" in i["value"]


def test_circl_strip_attachments_removes_embedded_files():
    body = json.dumps({"Event": {"Attribute": [
        {"type": "malware-sample", "value": "x.exe|abc", "data": "UEsDBBQ="},
        {"type": "attachment", "value": "shot.png", "data": "iVBOR"},
        {"type": "ip-dst", "value": "198.51.100.7", "to_ids": True, "data": "zz"}],
        "Object": [{"Attribute": [{"type": "attachment", "value": "a", "data": "b"}]}]}}).encode()
    out = json.loads(strip_attachments(body))["Event"]
    assert [a["type"] for a in out["Attribute"]] == ["ip-dst"] and "data" not in out["Attribute"][0]
    assert out["Object"][0]["Attribute"] == []


def test_circl_attribute_mapping_and_tags():
    assert attribute_iocs({"type": "ip-dst|port", "value": "198.51.100.7|443"}) == []  # documentation range: reserved
    assert attribute_iocs({"type": "ip-dst|port", "value": "45.9.168.192|443"}) == [("ip", "45.9.168.192")]
    assert attribute_iocs({"type": "url", "value": "http://bad.example/x"}) == [("url", "hxxp://bad[.]example/x")]
    assert attribute_iocs({"type": "filename|sha256", "value": "a.exe|" + "a" * 64}) == [("hash", "a" * 64)]
    links = tag_links(['misp-galaxy:threat-actor="Turla Group"', 'misp-galaxy:mitre-malware="Kali365 - S9044"',
                       'misp-galaxy:mitre-attack-pattern="Email Collection - T1114"', "tlp:clear"])
    assert links == {"actors": ["Turla Group"], "malware": ["kali365"], "techniques": ["T1114"]}


def test_otx_skips_without_key_and_parses_fixture(conn, monkeypatch):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    r = collectors.run_feed("otx", conn=conn)
    assert r["status"] == "skipped" and "OTX_API_KEY" in r["error"]
    _, rows = norm("otx")
    assert rows and {r["type"] for r in rows} >= {"ip", "domain"}


def test_seeded_new_sources_score_and_link(conn):
    srcs = {r[0] for r in conn.execute("SELECT DISTINCT source FROM sightings")}
    assert {"sslbl", "et_compromised", "cins", "blocklistde", "phishing_army", "circl"} <= srcs
    # single reputation lists stay below the malicious threshold on their own
    lone = db.one(conn, "SELECT MAX(confidence) c FROM indicators WHERE sources='[\"cins\"]'")
    assert lone["c"] is None or lone["c"] < 60
    assert conn.execute("SELECT COUNT(*) FROM relationships WHERE rel='reported-in'").fetchone()[0] > 0
    assert conn.execute("SELECT COUNT(*) FROM misp_events").fetchone()[0] > 0


def test_prune_source_drops_only_stale_rows(isolated_env):
    c = db.connect(isolated_env / "prune.db")
    old = db.now() - 40 * 86400
    db.upsert_indicator(c, type="ip", value="198.51.100.1", source="cins", observed_at=old)
    db.upsert_indicator(c, type="ip", value="198.51.100.2", source="cins")
    db.upsert_indicator(c, type="ip", value="198.51.100.3", source="cins", observed_at=old)
    db.upsert_indicator(c, type="ip", value="198.51.100.3", source="feodo")
    assert db.prune_source(c, "cins", 14) == 1
    left = {r[0]: json.loads(r[1]) for r in c.execute("SELECT value, sources FROM indicators")}
    assert left == {"198.51.100.2": ["cins"], "198.51.100.3": ["feodo"]}
    c.close()


def test_observation_history_counts_days(isolated_env):
    c = db.connect(isolated_env / "hist.db")
    day1 = 1794600000.0
    for t in (day1, day1 + 600, day1 + 86400, day1 + 3 * 86400):
        db.upsert_indicator(c, type="ip", value="198.51.100.9", source="cins", observed_at=t)
    s = db.one(c, "SELECT first_obs, last_obs, days_seen FROM sightings")
    assert s == {"first_obs": day1, "last_obs": day1 + 3 * 86400, "days_seen": 3}
    c.close()


def test_fetch_size_cap_transform_and_extra_hosts():
    big = httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * 5000))
    with pytest.raises(fetch.FetchError, match="byte cap"):
        fetch.get("https://www.circl.lu/doc/misp/feed-osint/a.json", feed="t-cap", transport=big,
                  host_interval_s=0, max_bytes=1000, retries=0)
    ok = httpx.MockTransport(lambda r: httpx.Response(200, content=b"abc"))
    r = fetch.get("https://www.circl.lu/doc/misp/feed-osint/b.json", feed="t-tr", transport=ok,
                  host_interval_s=0, transform=lambda b: b.upper())
    assert r.body == b"ABC"
    with pytest.raises(fetch.FetchError):
        fetch.get("https://rdap.verisign.com/com/v1/domain/x.com", feed="t-x", transport=ok, host_interval_s=0)
    assert fetch.get("https://rdap.verisign.com/com/v1/domain/x.com", feed="t-x", transport=ok, host_interval_s=0,
                     extra_hosts={"rdap.verisign.com"}).body == b"abc"
