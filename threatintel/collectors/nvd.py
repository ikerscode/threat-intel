"""NVD CVE API 2.0: CVSS and CWE for KEV CVEs.

Uses the `hasKev` filter so the whole KEV set arrives in a handful of paged
requests instead of one request per CVE. Without NVD_API_KEY the NVD limit is
5 requests per rolling 30 s, so pages are spaced 6.5 s apart. With a key the gap
drops to 0.7 s.
"""
from __future__ import annotations

import json

from .base import Collector

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
METRIC_ORDER = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")


def best_cvss(metrics: dict) -> dict | None:
    """Prefer the NVD primary score of the newest v3.x, then v4, then v2."""
    for key in METRIC_ORDER:
        items = metrics.get(key) or []
        if not items:
            continue
        primary = [m for m in items if m.get("type") == "Primary"] or items
        m = primary[0]
        data = m.get("cvssData", {})
        return {"score": data.get("baseScore"), "version": data.get("version"),
                "vector": data.get("vectorString"),
                "severity": data.get("baseSeverity") or m.get("baseSeverity")}
    return None


class NvdCollector(Collector):
    name = "nvd"
    title = "NVD CVE API 2.0"
    homepage = "https://nvd.nist.gov/developers/vulnerabilities"
    licence = "Public domain US Government data; NVD asks for the notice 'This product uses the NVD API but is not endorsed or certified by the NVD'"
    fixture_files = ("nvd.json",)
    optional_env = "NVD_API_KEY"

    def fetch(self, conn=None):
        key = self.env(self.optional_env)
        headers = {"apiKey": key} if key else {}
        interval = 0.7 if key else 6.5
        size = int(self.cfg.get("page_size", 500))
        start, total, vulns = 0, None, []
        while total is None or start < total:
            res = self.get(f"{API}?hasKev&resultsPerPage={size}&startIndex={start}", headers=headers,
                           host_interval_s=interval)
            page = json.loads(res.body)
            total = page.get("totalResults", 0)
            vulns.extend(page.get("vulnerabilities", []))
            start += size
            if not page.get("vulnerabilities"):
                break
        return {"totalResults": total, "vulnerabilities": vulns}

    def normalise(self, raw) -> list[dict]:
        out = []
        for item in raw.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cvss = best_cvss(cve.get("metrics", {}))
            cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                           if d.get("value", "").startswith("CWE-")})
            out.append({"cve": cve.get("id", "").upper(), "cvss": cvss, "cwes": cwes,
                        "published": (cve.get("published") or "")[:10]})
        return out

    def store(self, conn, records) -> int:
        n = 0
        for r in records:
            c = r["cvss"] or {}
            cur = conn.execute(
                """UPDATE vulnerabilities SET cvss=?, cvss_version=?, cvss_vector=?, severity=?, nvd_published=?,
                   cwes=CASE WHEN ?='[]' THEN cwes ELSE ? END WHERE cve=?""",
                (c.get("score"), c.get("version"), c.get("vector"), c.get("severity"), r["published"],
                 json.dumps(r["cwes"]), json.dumps(r["cwes"]), r["cve"]))
            n += cur.rowcount
        return n
