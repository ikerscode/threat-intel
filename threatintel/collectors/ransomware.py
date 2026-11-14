"""ransomware.live public API v2: groups and victims.

Endpoints used: /v2/groups, /v2/recentvictims and /v2/victims/{year}/{month}
for the current and previous month (enough for 7/30 day activity). The free API
answers "1 per 1 minute" when called faster, so requests to this host are spaced
62 s apart (host_interval_s in config) and a full run takes a few minutes.

Leak-site addresses (.onion "locations", victim "claim_url") are deliberately
dropped: they are not needed for analysis and we never contact them.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .. import db
from .base import Collector

API = "https://api.ransomware.live/v2"


def _months(n: int) -> list[tuple[int, int]]:
    now = datetime.now(timezone.utc)
    y, m, out = now.year, now.month, []
    for _ in range(n):
        out.append((y, m))
        y, m = (y, m - 1) if m > 1 else (y - 1, 12)
    return out


def _list(value) -> list:
    if isinstance(value, list):
        return value
    return []


class RansomwareCollector(Collector):
    name = "ransomware"
    title = "ransomware.live"
    homepage = "https://www.ransomware.live/"
    licence = "Free public API, attribution to ransomware.live; data is scraped from leak sites (unverified claims)"
    fixture_files = ("ransomware-groups.json", "ransomware-victims.json")

    def fetch(self, conn=None):
        groups = json.loads(self.get(f"{API}/groups").body)
        victims = json.loads(self.get(f"{API}/recentvictims").body)
        for y, m in _months(int(self.cfg.get("months", 2))):
            victims += json.loads(self.get(f"{API}/victims/{y}/{m:02d}").body)
        return {"groups": groups, "victims": victims}

    def load_fixture(self, fixture_dir):
        return {"groups": json.loads((fixture_dir / self.fixture_files[0]).read_text()),
                "victims": json.loads((fixture_dir / self.fixture_files[1]).read_text())}

    def normalise(self, raw) -> dict:
        groups = []
        for g in raw.get("groups", []):
            if not isinstance(g, dict) or not g.get("name"):
                continue
            alt = g.get("altname")
            techniques = sorted({t["technique_id"] for tac in _list(g.get("ttps")) for t in tac.get("techniques", [])
                                 if t.get("technique_id")})
            tools = []
            for item in _list(g.get("tools")):
                if isinstance(item, dict):
                    for vals in item.values():
                        tools += [v for v in (vals if isinstance(vals, list) else [vals]) if isinstance(v, str)]
                elif isinstance(item, str):
                    tools.append(item)
            groups.append({"name": g["name"], "aliases": [alt] if alt and alt != "None" else [],
                           "description": (g.get("description") or "")[:600], "url": g.get("url"),
                           "techniques": techniques, "tools": sorted(set(tools))[:60]})
        victims, seen = [], set()
        for v in raw.get("victims", []):
            if not isinstance(v, dict) or not v.get("victim") or not v.get("group"):
                continue
            key = (v["group"], v["victim"])
            if key in seen:
                continue
            seen.add(key)
            victims.append({"group": v["group"], "victim": v["victim"][:200], "domain": v.get("domain") or None,
                            "sector": v.get("activity") or "Not Found", "country": v.get("country") or "",
                            "attack_date": (v.get("attackdate") or "")[:10] or None,
                            "discovered": (v.get("discovered") or "")[:19] or None, "ref_url": v.get("url")})
        return {"groups": groups, "victims": victims}

    def store(self, conn, rec) -> int:
        conn.execute("DELETE FROM relationships WHERE source='ransomware'")
        for g in rec["groups"]:
            conn.execute("""INSERT OR REPLACE INTO actor_records(source, source_id, name, aliases, description, url, extra)
                            VALUES ('ransomware',?,?,?,?,?,?)""",
                         (g["name"], g["name"], json.dumps(g["aliases"]), g["description"], g["url"],
                          json.dumps({"techniques": g["techniques"], "tools": g["tools"]})))
            for t in g["techniques"]:
                db.add_rel(conn, f"rwgroup:{g['name']}", "uses", f"technique:{t}", self.name)
        for v in rec["victims"]:
            conn.execute("""INSERT INTO victims(group_name, victim, domain, sector, country, attack_date, discovered, ref_url)
                            VALUES (?,?,?,?,?,?,?,?)
                            ON CONFLICT(group_name, victim) DO UPDATE SET sector=excluded.sector,
                              country=excluded.country, attack_date=COALESCE(excluded.attack_date, victims.attack_date),
                              discovered=COALESCE(victims.discovered, excluded.discovered)""",
                         (v["group"], v["victim"], v["domain"], v["sector"], v["country"], v["attack_date"],
                          v["discovered"], v["ref_url"]))
        return len(rec["groups"]) + len(rec["victims"])
