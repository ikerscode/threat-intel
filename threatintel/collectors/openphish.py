"""OpenPhish community feed (plain text, one phishing URL per line).

openphish.com/feed.txt now redirects to the public GitHub copy, which is what we
request directly. The phishing URLs are never visited: they are parsed as text,
stored defanged and analysed offline (host, registered domain, brand keywords).
"""
from __future__ import annotations

from .. import db, defang, psl
from .base import Collector

URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"


class OpenphishCollector(Collector):
    name = "openphish"
    title = "OpenPhish community feed"
    homepage = "https://openphish.com/"
    licence = "Community feed, free for non-commercial use (OpenPhish terms)"
    fixture_files = ("openphish-feed.txt",)

    def fetch(self, conn=None):
        return self.get(URL).body.decode("utf-8", "replace")

    def normalise(self, raw: str) -> list[dict]:
        out, seen = [], set()
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            url = defang.canonical_url(line)          # accepts fanged or defanged input
            host = defang.url_host(url)
            if not host:
                continue
            stored = defang.defang_url(url)
            if stored in seen:
                continue
            seen.add(stored)
            out.append({"url": stored, "host": host, "reg_domain": psl.registered_domain(host)})
        return out

    def store(self, conn, records) -> int:
        ts = db.now()
        for r in records:
            is_ip = psl.is_ip(r["host"])
            host = r["host"] if is_ip else defang.defang_domain(r["host"])
            reg = r["reg_domain"] if is_ip else defang.defang_domain(r["reg_domain"])
            db.upsert_indicator(conn, type="url", value=r["url"], source=self.name, first_seen=ts, last_seen=ts,
                                tags=["phishing"], host=host, reg_domain=reg)
            if is_ip:
                db.upsert_indicator(conn, type="ip", value=r["host"], source=self.name, tags=["phishing-host"])
            else:
                db.upsert_indicator(conn, type="domain", value=host, source=self.name, tags=["phishing-host"],
                                    reg_domain=reg)
        return len(records)
