"""Phishing Army community blocklist (active phishing domains, plain text).

Source: https://phishing.army/download/phishing_army_blocklist.txt (no key).
It aggregates PhishTank, OpenPhish, CERT.PL, urlscan.io and others into about
145 000 domains, regenerated every few hours. We keep a stable hash sample
(`limit` in feeds.toml) so the brand analysis covers a second, much larger
phishing population than OpenPhish without storing the whole list.

The file deliberately contains the harmless test domain amiprotected.it; it is
dropped here. Domains are stored defanged and never resolved or visited.
"""
from __future__ import annotations

from .. import db, defang, psl
from .base import Collector, comment_lines, stable_sample

URL = "https://phishing.army/download/phishing_army_blocklist.txt"
TEST_DOMAINS = {"amiprotected.it", "www.amiprotected.it"}


class PhishingArmyCollector(Collector):
    name = "phishing_army"
    title = "Phishing Army blocklist"
    homepage = "https://phishing.army/"
    licence = "Free for personal and individual use (phishing.army/license)"
    fixture_files = ("phishing-army.txt",)

    def fetch(self, conn=None):
        return self.get(URL).body.decode("utf-8", "replace")

    def normalise(self, raw: str) -> list[dict]:
        hosts = []
        for line in comment_lines(raw, ("#",)):
            host = defang.refang(line).lower().strip(".")   # the fixture is stored defanged
            if host in TEST_DOMAINS or not defang.DOMAIN_RE.match(host):
                continue
            hosts.append(host)
        self.listed = len(set(hosts))
        keep = stable_sample(hosts, int(self.cfg.get("limit", 4000)))
        return [{"host": h, "reg_domain": psl.registered_domain(h)} for h in keep]

    def store(self, conn, records) -> int:
        ts = db.now()
        for r in records:
            db.upsert_indicator(conn, type="domain", value=defang.defang_domain(r["host"]), source=self.name,
                                first_seen=ts, last_seen=ts, tags=["phishing", "phishing-host"],
                                reg_domain=defang.defang_domain(r["reg_domain"]))
        db.set_meta(conn, f"listed:{self.name}", {"listed": getattr(self, "listed", len(records)), "kept": len(records)})
        return len(records)
