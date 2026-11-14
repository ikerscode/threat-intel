"""FIRST EPSS scores for the CVEs we track.

Source: https://api.first.org/data/v1/epss . Queried in batches of up to 100 CVEs
per request (the API accepts a comma separated cve= list).
"""
from __future__ import annotations

import json

from .base import Collector, SkipFeed

API = "https://api.first.org/data/v1/epss"


class EpssCollector(Collector):
    name = "epss"
    title = "FIRST EPSS"
    homepage = "https://www.first.org/epss/"
    licence = "Free to use with attribution (FIRST EPSS usage guidance)"
    fixture_files = ("epss.json",)

    def fetch(self, conn=None):
        cves = [r[0] for r in conn.execute("SELECT cve FROM vulnerabilities ORDER BY cve")]
        if not cves:
            raise SkipFeed("no CVEs in the database yet; collect kev first")
        size = int(self.cfg.get("batch_size", 100))
        data = []
        for i in range(0, len(cves), size):
            batch = cves[i:i + size]
            res = self.get(f"{API}?cve={','.join(batch)}&limit={size}")
            data.extend(json.loads(res.body).get("data", []))
        return {"status": "OK", "data": data}

    def normalise(self, raw) -> list[dict]:
        out = []
        for d in raw.get("data", []):
            out.append({"cve": d["cve"].upper(), "epss": float(d["epss"]),
                        "percentile": float(d["percentile"]), "date": d.get("date")})
        return out

    def store(self, conn, records) -> int:
        n = 0
        for r in records:
            cur = conn.execute("UPDATE vulnerabilities SET epss=?, epss_percentile=?, epss_date=? WHERE cve=?",
                               (r["epss"], r["percentile"], r["date"], r["cve"]))
            n += cur.rowcount
        return n
