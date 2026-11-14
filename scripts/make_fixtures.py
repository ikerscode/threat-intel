"""Rebuild fixtures/ from the live cache (data/cache) after a live `collect`.

Usage:  python scripts/make_fixtures.py

Trims each feed to a few hundred rows, keeps what the correlation demo needs
(overlaps, ATT&CK objects linked to the kept groups) and strips fields we never
want in the repo (leak-site .onion addresses, screenshots). URLs from OpenPhish
are written defanged. URLhaus and ThreatFox now need an API key, so their
fixtures are synthetic samples in the real API format (see MANIFEST.json).
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from threatintel import aliases, defang  # noqa: E402
from threatintel.collectors.attack import CVE_IN_TEXT, ext_id  # noqa: E402

CACHE = ROOT / "data" / "cache"
OUT = ROOT / "fixtures"
RNG = random.Random(20261113)


def cached(feed: str, url_part: str) -> list[tuple[str, bytes]]:
    out = []
    for meta in sorted((CACHE / feed).glob("*.meta.json")):
        m = json.loads(meta.read_text())
        if url_part in m.get("url", ""):
            out.append((m["url"], meta.with_name(meta.name.replace(".meta.json", ".body")).read_bytes()))
    return out


def write(name: str, obj) -> None:
    p = OUT / name
    if isinstance(obj, str):
        p.write_text(obj, encoding="utf-8")
    else:
        p.write_text(json.dumps(obj, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"{name:<34} {p.stat().st_size / 1024:8.1f} KB")


# ------------------------------------------------------------------ ransomware.live

def ransomware():
    groups = json.loads(cached("ransomware", "/v2/groups")[0][1])
    victims = []
    for url, body in cached("ransomware", "/v2/"):
        if "/groups" in url:
            continue
        victims += json.loads(body)
    seen, uniq = set(), []
    for v in victims:
        k = (v.get("group"), v.get("victim"))
        if k not in seen and v.get("discovered"):
            seen.add(k)
            uniq.append(v)
    uniq.sort(key=lambda v: v["discovered"])
    keep = RNG.sample(uniq, min(450, len(uniq)))
    keep.sort(key=lambda v: v["discovered"], reverse=True)
    fields = ("activity", "attackdate", "country", "discovered", "domain", "group", "url", "victim")
    vic = [{k: v.get(k) for k in fields} for v in keep]
    names = {v["group"] for v in vic}
    curated = {aliases.canonical_group(k) for k in aliases.curated_entries("groups")}
    gkeep = []
    for g in groups:
        if g["name"] in names or aliases.canonical_group(g["name"]) in curated:
            gkeep.append({"name": g["name"], "altname": g.get("altname"), "added_date": g.get("added_date"),
                          "description": (g.get("description") or "")[:400], "url": g.get("url"),
                          "ttps": g.get("ttps") or [], "tools": g.get("tools") or []})
    write("ransomware-victims.json", vic)
    write("ransomware-groups.json", gkeep)
    return gkeep, vic


# ------------------------------------------------------------------ ATT&CK

def attack(rw_groups):
    raw = json.loads(cached("attack", "enterprise-attack.json")[0][1])
    objs = [o for o in raw["objects"] if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_id = {o["id"]: o for o in objs}
    rw_keys = set()
    for g in rw_groups:
        rw_keys.add(aliases.canonical_group(g["name"]))
        if g.get("altname"):
            rw_keys.add(aliases.canonical_group(g["altname"]))
    wanted_names = {aliases.canonical_group(n) for n in (
        "APT28", "Lazarus Group", "FIN7", "Wizard Spider", "Sandworm Team", "Volt Typhoon",
        "Scattered Spider", "TA505", "FIN11", "Indrik Spider")}
    groups = set()
    for o in objs:
        if o["type"] != "intrusion-set":
            continue
        keys = {aliases.canonical_group(o["name"])} | {aliases.canonical_group(a) for a in o.get("aliases", [])}
        if keys & (rw_keys | wanted_names):
            groups.add(o["id"])
    rels = [o for o in objs if o["type"] == "relationship"]
    software = set()
    for r in rels:
        if r["relationship_type"] == "uses" and r["source_ref"] in groups and r["target_ref"].startswith(("malware--", "tool--")):
            software.add(r["target_ref"])
    fam_names = {aliases.canonical_malware(n) for n in aliases.curated_entries("malware")}
    tool_names = {aliases.norm(t) for g in rw_groups for item in (g.get("tools") or []) if isinstance(item, dict)
                  for vals in item.values() for t in (vals if isinstance(vals, list) else [])}
    for o in objs:
        if o["type"] in ("malware", "tool"):
            names = [o["name"], *o.get("x_mitre_aliases", [])]
            keys = {aliases.canonical_malware(n) for n in names} | {aliases.norm(n) for n in names}
            strip = {aliases.strip_version(k) for k in keys}
            if keys & fam_names or keys & tool_names or (
                    "ransomware" in (o.get("description") or "").lower() and (keys | strip) & rw_keys):
                software.add(o["id"])
    # software -> technique edges only for malware families (tool behaviour is not needed for the demo)
    families = {sid for sid in software if sid.startswith("malware--") and (
        "ransomware" in (by_id[sid].get("description") or "").lower()
        or aliases.canonical_malware(by_id[sid]["name"]) in fam_names)}
    techniques = set()
    for r in rels:
        if r["relationship_type"] == "uses" and (r["source_ref"] in groups or r["source_ref"] in families) \
                and r["target_ref"].startswith("attack-pattern--"):
            techniques.add(r["target_ref"])
    # ransomware.live TTP ids
    rw_tids = {t["technique_id"] for g in rw_groups for tac in g.get("ttps") or [] for t in tac.get("techniques", [])}
    for o in objs:
        if o["type"] == "attack-pattern" and ext_id(o) in rw_tids:
            techniques.add(o["id"])
    # parents of sub-techniques
    tid_to_obj = {ext_id(o): o for o in objs if o["type"] == "attack-pattern"}
    for t in list(techniques):
        aid = ext_id(by_id[t])
        if aid and "." in aid and aid.split(".")[0] in tid_to_obj:
            techniques.add(tid_to_obj[aid.split(".")[0]]["id"])
    keep_ids = groups | software | techniques
    out = []

    def slim(o):
        o = dict(o)
        if "description" in o:
            d = o["description"]
            cves = sorted(set(CVE_IN_TEXT.findall(d)))
            o["description"] = d[:300] + (" ... mentions " + ", ".join(cves) if cves and not all(c in d[:300] for c in cves) else "")
        o["external_references"] = [r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"]
        for k in ("x_mitre_contributors", "x_mitre_data_sources", "x_mitre_detection", "x_mitre_permissions_required",
                  "x_mitre_defense_bypassed", "x_mitre_system_requirements", "x_mitre_effective_permissions",
                  "x_mitre_remote_support", "x_mitre_impact_type", "object_marking_refs", "x_mitre_attack_spec_version",
                  "x_mitre_modified_by_ref", "x_mitre_domains", "x_mitre_platforms"):
            o.pop(k, None)
        return o

    for o in objs:
        if o["type"] in ("x-mitre-tactic", "x-mitre-matrix") or o["id"] in keep_ids:
            out.append(slim(o))
    for r in rels:
        if r["relationship_type"] not in ("uses", "subtechnique-of") or r["source_ref"] not in keep_ids \
                or r["target_ref"] not in keep_ids:
            continue
        if r["source_ref"].startswith("tool--") and r["target_ref"].startswith("attack-pattern--"):
            continue
        r = {k: r[k] for k in ("type", "id", "relationship_type", "source_ref", "target_ref", "description") if k in r}
        # relationship text is only needed for the CVE ids it mentions
        cves = sorted(set(c.upper() for c in CVE_IN_TEXT.findall(r.get("description", ""))))
        r.pop("external_references", None)
        if cves:
            r["description"] = "Exploited " + ", ".join(cves)
        else:
            r.pop("description", None)
        out.append(r)
    for o in out:
        if o["type"] in ("attack-pattern", "malware", "tool", "x-mitre-tactic"):
            o["description"] = o.get("description", "")[:160]
        for k in ("spec_version", "created", "modified", "created_by_ref", "revoked", "x_mitre_deprecated", "x_mitre_version"):
            o.pop(k, None)
    p = OUT / "attack-enterprise-trimmed.json"
    p.write_text(json.dumps({"type": "bundle", "id": raw["id"], "objects": out}, separators=(",", ":")), encoding="utf-8")
    print(f"{p.name:<34} {p.stat().st_size / 1024:8.1f} KB")
    exploited = set()
    for o in out:
        exploited |= set(c.upper() for c in CVE_IN_TEXT.findall(o.get("description", "")))
    print(f"   attack: {len(groups)} groups, {len(software)} software, {len(techniques)} techniques")
    return exploited


# ------------------------------------------------------------------ vulnerabilities

def vulns(extra_cves):
    kev = json.loads(cached("kev", "known_exploited")[0][1])
    vs = kev["vulnerabilities"]
    ransom = [v for v in vs if v.get("knownRansomwareCampaignUse") == "Known"]
    recent = sorted(vs, key=lambda v: v["dateAdded"], reverse=True)[:60]
    mentioned = [v for v in vs if v["cveID"] in extra_cves]
    keep = {v["cveID"]: v for v in RNG.sample(ransom, min(180, len(ransom))) + recent + mentioned}
    kev_out = dict(kev)
    kev_out["vulnerabilities"] = sorted(keep.values(), key=lambda v: v["dateAdded"], reverse=True)
    kev_out["count"] = len(kev_out["vulnerabilities"])
    write("kev.json", kev_out)
    cves = set(keep)
    epss = []
    for _, body in cached("epss", "api.first.org"):
        epss += [d for d in json.loads(body).get("data", []) if d["cve"] in cves]
    write("epss.json", {"status": "OK", "data": epss})
    nvd = []
    for _, body in cached("nvd", "services.nvd.nist.gov"):
        for item in json.loads(body).get("vulnerabilities", []):
            c = item["cve"]
            if c["id"] in cves:
                metrics = {k: [m for m in v if m.get("type") == "Primary"][:1] or v[:1] for k, v in c.get("metrics", {}).items()}
                nvd.append({"cve": {"id": c["id"], "published": c.get("published"), "metrics": metrics,
                                    "weaknesses": c.get("weaknesses", [])}})
    write("nvd.json", {"totalResults": len(nvd), "vulnerabilities": nvd})


# ------------------------------------------------------------------ IP feeds

def ip_feeds():
    feodo = json.loads(cached("feodo", "ipblocklist.json")[0][1])
    write("feodo-ipblocklist.json", feodo)
    phish = cached("openphish", "feed.txt")[0][1].decode().split()
    write("openphish-feed.txt", "\n".join(defang.defang_url(u) for u in phish[:300]) + "\n")
    tor = [l.strip() for l in cached("tor", "torbulkexitlist")[0][1].decode().splitlines() if l.strip()]
    drop = []
    for _, body in cached("spamhaus", "drop_v"):
        drop += [json.loads(l) for l in body.decode().splitlines() if l.strip().startswith("{")]
    nets = [(ipaddress.ip_network(d["cidr"]), d) for d in drop if "cidr" in d]
    inside = [ip for ip in tor if any(ipaddress.ip_address(ip) in n for n, _ in nets if n.version == ipaddress.ip_address(ip).version)]
    tor_keep = inside + RNG.sample([t for t in tor if t not in inside], 300 - len(inside))
    write("tor-exits.txt", "\n".join(tor_keep) + "\n")
    needed = {str(d["cidr"]) for n, d in nets if any(ipaddress.ip_address(ip) in n for ip in inside if ipaddress.ip_address(ip).version == n.version)}
    others = [d for n, d in nets if d["cidr"] not in needed]
    drop_keep = [d for n, d in nets if d["cidr"] in needed] + RNG.sample(others, 300 - len(needed))
    meta = [d for d in drop if d.get("type") == "metadata"]
    write("spamhaus-drop.jsonl", "\n".join(json.dumps(d) for d in sorted(drop_keep, key=lambda d: d["cidr"]) + meta) + "\n")
    ips = set(tor_keep) | {f["ip_address"] for f in feodo}
    ips |= {defang.url_host(u) for u in phish[:300] if defang.detect(defang.url_host(u)) == "ip"}
    return ips


def ip2asn_subset(ips):
    import bisect
    path = ROOT / "data" / "ip2asn" / "ip2asn-combined.tsv"
    rows = []
    with open(path) as fh:
        for line in fh:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 5:
                rows.append((p[0], p[1], line))
    keep = set()
    by_ver = {4: [], 6: []}
    for a, b, line in rows:
        try:
            ia, ib = ipaddress.ip_address(a), ipaddress.ip_address(b)
        except ValueError:
            continue
        by_ver[ia.version].append((int(ia), int(ib), line))
    for v in by_ver:
        by_ver[v].sort()
    starts = {v: [r[0] for r in by_ver[v]] for v in by_ver}
    for ip in ips:
        a = ipaddress.ip_address(ip)
        i = bisect.bisect_right(starts[a.version], int(a)) - 1
        if i >= 0 and int(a) <= by_ver[a.version][i][1]:
            keep.add(by_ver[a.version][i][2])
    write("ip2asn-subset.tsv", "".join(sorted(keep)))


# ------------------------------------------------------------------ synthetic abuse.ch samples

def fake_hash(seed: str) -> str:
    return hashlib.sha256(f"seclab synthetic fixture {seed}".encode()).hexdigest()


def synthetic_abusech():
    """Documentation-range IPs (RFC 5737) and reserved .example/.test names only."""
    base = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
    fams = [("win.cobalt_strike", "Cobalt Strike"), ("win.asyncrat", "AsyncRAT"), ("win.remcos", "Remcos"),
            ("win.lumma", "Lumma Stealer"), ("elf.mirai", "Mirai"), ("win.qakbot", "QakBot"),
            ("win.sliver", "Sliver"), ("win.agent_tesla", "Agent Tesla"), ("win.lockbit", "LockBit"),
            ("win.darkgate", "DarkGate")]
    nets = ["192.0.2.", "198.51.100.", "203.0.113."]
    tf = []
    n = 0
    for i, (mal, printable) in enumerate(fams):
        for j in range(5):
            n += 1
            ip = f"{nets[(i + j) % 3]}{10 + i * 8 + j}"
            ts = (base - timedelta(hours=7 * n)).strftime("%Y-%m-%d %H:%M:%S UTC")
            tf.append({"id": str(900000 + n), "ioc": f"{ip}:{443 if j % 2 else 8080}", "threat_type": "botnet_cc",
                       "threat_type_desc": "Indicator that identifies a botnet command&control server (C&C)",
                       "ioc_type": "ip:port", "ioc_type_desc": "ip:port combination that is used for botnet Command&control (C&C)",
                       "malware": mal, "malware_printable": printable, "malware_alias": None, "malware_malpedia": None,
                       "confidence_level": [100, 75, 50][j % 3], "first_seen": ts, "last_seen": None,
                       "reference": None, "reporter": "seclab-fixture", "tags": [printable.lower().replace(" ", ""), "synthetic"]})
        tf.append({"id": str(910000 + i), "ioc": f"update-{printable.lower().replace(' ', '')}.example",
                   "threat_type": "payload_delivery", "threat_type_desc": "Indicator that identifies a malware distribution server (payload delivery)",
                   "ioc_type": "domain", "ioc_type_desc": "Domain that is used for payload delivery",
                   "malware": mal, "malware_printable": printable, "malware_alias": None, "malware_malpedia": None,
                   "confidence_level": 75, "first_seen": (base - timedelta(days=i)).strftime("%Y-%m-%d %H:%M:%S UTC"),
                   "last_seen": None, "reference": None, "reporter": "seclab-fixture", "tags": ["synthetic"]})
        tf.append({"id": str(920000 + i), "ioc": fake_hash(printable), "threat_type": "payload",
                   "threat_type_desc": "Indicator that identifies a malware sample (payload)",
                   "ioc_type": "sha256_hash", "ioc_type_desc": "SHA256 hash of a malware sample",
                   "malware": mal, "malware_printable": printable, "malware_alias": None, "malware_malpedia": None,
                   "confidence_level": 100, "first_seen": (base - timedelta(days=i, hours=3)).strftime("%Y-%m-%d %H:%M:%S UTC"),
                   "last_seen": None, "reference": None, "reporter": "seclab-fixture", "tags": ["synthetic"]})
    write("threatfox-iocs.json", {"query_status": "ok", "data": tf})
    uh = []
    hosts = ["198.51.100.20", "198.51.100.21", "cdn-files.example", "dl.cdn-files.example", "203.0.113.42",
             "panel.badhost.test", "static.badhost.test", "192.0.2.77"]
    tags = [["elf", "mirai"], ["elf", "mirai"], ["exe", "AsyncRAT"], ["exe", "Remcos"], ["sh", "mirai"],
            ["dll", "QakBot"], ["zip", "Lumma"], ["exe", "CobaltStrike"]]
    for k in range(40):
        h, t = hosts[k % len(hosts)], tags[k % len(tags)]
        url = f"http://{h}/{['bins', 'files', 'dl', 'x'][k % 4]}/{fake_hash(str(k))[:10]}.{t[0]}"
        uh.append({"id": str(3000000 + k), "urlhaus_reference": None,
                   "url": defang.defang_url(url), "url_status": "online" if k % 3 else "offline",
                   "host": defang.defang_domain(h), "date_added": (base - timedelta(hours=11 * k)).strftime("%Y-%m-%d %H:%M:%S UTC"),
                   "threat": "malware_download", "blacklists": {}, "reporter": "seclab-fixture", "larted": "false",
                   "tags": t + ["synthetic"]})
    write("urlhaus-recent.json", {"query_status": "ok", "urls": uh})


def main():
    OUT.mkdir(exist_ok=True)
    rw_groups, _ = ransomware()
    exploited = attack(rw_groups)
    vulns(exploited)
    ips = ip_feeds()
    ip2asn_subset(ips)
    synthetic_abusech()
    files = sorted(p.name for p in OUT.iterdir() if p.name != "MANIFEST.json")
    manifest = {
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "note": "Trimmed snapshots of live feeds fetched on the creation date. URLs are stored defanged.",
        "synthetic": {
            "urlhaus-recent.json": "Synthetic sample in URLhaus API format (the API needs an Auth-Key). RFC 5737 IPs and .example/.test names only; hashes are made up.",
            "threatfox-iocs.json": "Synthetic sample in ThreatFox API format (the API needs an Auth-Key). RFC 5737 IPs and .example names only; hashes are made up.",
        },
        "files": files,
    }
    write("MANIFEST.json", manifest)


if __name__ == "__main__":
    main()
