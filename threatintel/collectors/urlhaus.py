"""abuse.ch URLhaus recent malware URLs.

The anonymous CSV/text exports (urlhaus.abuse.ch/downloads/...) now return
410 Gone, so this collector uses the URLhaus API, which needs a free Auth-Key
from https://auth.abuse.ch/ . Set ABUSECH_AUTH_KEY to enable it; without it the
feed is skipped cleanly. The URLs themselves are never requested; they are
stored defanged.
"""
from __future__ import annotations

import json

from .. import aliases, db, defang, psl, timeutil
from .base import Collector

API = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/"


class UrlhausCollector(Collector):
    name = "urlhaus"
    title = "abuse.ch URLhaus"
    homepage = "https://urlhaus.abuse.ch/"
    licence = "CC0 1.0 (abuse.ch terms of use)"
    fixture_files = ("urlhaus-recent.json",)
    requires_env = "ABUSECH_AUTH_KEY"

    def fetch(self, conn=None):
        limit = int(self.cfg.get("limit", 500))
        res = self.get(API.format(limit=limit), headers={"Auth-Key": self.env(self.requires_env)})
        return json.loads(res.body)

    def normalise(self, raw) -> list[dict]:
        out = []
        for u in raw.get("urls", []):
            url = u.get("url") or ""
            if not url:
                continue
            tags = [t for t in (u.get("tags") or []) if t]
            host = defang.url_host(url)
            families = [aliases.canonical_malware(t) for t in tags if not aliases.is_generic_tag(t)]
            out.append({
                "url": defang.defang_url(defang.canonical_url(url)),
                "host": host, "reg_domain": psl.registered_domain(host),
                "threat": u.get("threat"), "status": u.get("url_status"), "tags": tags,
                "malware": families[0] if families else None,
                "first_seen": timeutil.parse(u.get("date_added")),
                "reference": u.get("urlhaus_reference"),
            })
        return out

    def store(self, conn, records) -> int:
        for r in records:
            host_is_ip = psl.is_ip(r["host"])
            db.upsert_indicator(
                conn, type="url", value=r["url"], source=self.name, first_seen=r["first_seen"],
                tags=["malware-distribution"] + [f"tag:{t}" for t in r["tags"]], malware=r["malware"],
                host=r["host"] if host_is_ip else defang.defang_domain(r["host"]),
                reg_domain=r["reg_domain"] if host_is_ip else defang.defang_domain(r["reg_domain"]),
                extra={"threat": r["threat"], "status": r["status"], "reference": r["reference"]})
            if host_is_ip:
                db.upsert_indicator(conn, type="ip", value=r["host"], source=self.name, first_seen=r["first_seen"],
                                    tags=["malware-distribution"], malware=r["malware"])
            elif r["host"]:
                db.upsert_indicator(conn, type="domain", value=defang.defang_domain(r["host"]), source=self.name,
                                    first_seen=r["first_seen"], tags=["malware-distribution"], malware=r["malware"],
                                    reg_domain=defang.defang_domain(r["reg_domain"]))
            for t in r["tags"]:
                if aliases.is_generic_tag(t):
                    continue
                db.add_rel(conn, f"url:{r['url']}", "tagged", f"malware:{aliases.canonical_malware(t)}", self.name)
        return len(records)
