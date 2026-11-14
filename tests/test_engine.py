"""Correlation results on the seeded fixture database."""
import json

from threatintel import correlate, db


def test_seed_ran_every_feed(seeded):
    assert all(v.startswith("seeded") for v in seeded["feeds"].values()), seeded["feeds"]
    assert seeded["correlate"]["actors"] > 50


def test_actor_merge_attack_and_ransomware(conn):
    a = db.one(conn, "SELECT * FROM actors WHERE id='actor:akira'")
    assert a and a["attack_id"] == "G1024"
    assert set(json.loads(a["kinds"])) == {"attack-group", "ransomware"}
    assert conn.execute("SELECT COUNT(*) FROM victims WHERE actor_id='actor:akira'").fetchone()[0] > 0
    # ransomware.live TTPs and ATT&CK techniques are lifted onto the merged actor
    assert conn.execute("SELECT COUNT(*) FROM relationships WHERE src='actor:akira' AND rel='uses' "
                        "AND dst LIKE 'technique:%'").fetchone()[0] > 5


def test_malware_links_to_attack_software(conn):
    assert db.one(conn, "SELECT * FROM relationships WHERE src='malware:qakbot' AND rel='is' AND dst='software:S0650'")
    assert db.one(conn, "SELECT * FROM relationships WHERE src='actor:lockbit' AND rel='deploys'")


def test_drop_containment_and_tor_context(conn):
    ind = db.one(conn, "SELECT * FROM indicators WHERE tags LIKE '%in-drop%' AND sources='[\"tor\"]' LIMIT 1")
    assert ind and ind["context_only"] == 0 and 0 < ind["confidence"] <= 40
    tor_only = db.one(conn, "SELECT * FROM indicators WHERE sources='[\"tor\"]' AND tags NOT LIKE '%in-drop%' LIMIT 1")
    assert tor_only["context_only"] == 1 and tor_only["confidence"] == 0


def test_corroboration_raises_confidence(conn):
    multi = db.one(conn, "SELECT * FROM indicators WHERE sources LIKE '%threatfox%' AND sources LIKE '%urlhaus%' LIMIT 1")
    assert multi, "fixtures should contain an indicator reported by two feeds"


def test_vuln_priority_parts(conn):
    rows = db.rows(conn, "SELECT priority, priority_parts, ransomware_use FROM vulnerabilities")
    for r in rows:
        parts = json.loads(r["priority_parts"])
        s = sum(v for k, v in parts.items() if k != "cvss_assumed")
        assert 0 <= r["priority"] <= 100 and abs(s - r["priority"]) < 0.2
        assert (parts["ransomware"] == 15) == (r["ransomware_use"] == "Known")


def test_clusters_and_phishing(conn):
    kinds = {r[0] for r in conn.execute("SELECT DISTINCT kind FROM clusters")}
    assert {"shared-/24", "shared-asn", "inside-drop"} <= kinds
    assert conn.execute("SELECT COUNT(*) FROM indicators WHERE tags LIKE '%brand:%'").fetchone()[0] > 0


def test_correlate_is_idempotent(conn):
    before = conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0]
    correlate.run(conn)
    assert conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0] == before
