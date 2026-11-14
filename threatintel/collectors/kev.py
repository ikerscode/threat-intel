"""CISA Known Exploited Vulnerabilities catalogue.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (JSON feed).
Gives the CVE list, vendor/product, date added, due date and the
knownRansomwareCampaignUse flag ("Known" / "Unknown").
"""
from __future__ import annotations

import json

from .. import db
from .base import Collector

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def product_node(vendor: str, product: str) -> str:
    return f"product:{(vendor or '').strip().lower()}/{(product or '').strip().lower()}"


def vendor_node(vendor: str) -> str:
    return f"vendor:{(vendor or '').strip().lower()}"


class KevCollector(Collector):
    name = "kev"
    title = "CISA KEV catalogue"
    homepage = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    licence = "US Government work, public domain (CC0 1.0 per cisa.gov)"
    fixture_files = ("kev.json",)

    def fetch(self, conn=None):
        return json.loads(self.get(URL).body)

    def normalise(self, raw) -> list[dict]:
        out = []
        for v in raw.get("vulnerabilities", []):
            out.append({
                "cve": v["cveID"].upper(),
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "name": v.get("vulnerabilityName", ""),
                "description": v.get("shortDescription", ""),
                "date_added": v.get("dateAdded"),
                "due_date": v.get("dueDate"),
                "ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
                "required_action": v.get("requiredAction", ""),
                "cwes": v.get("cwes") or [],
            })
        return out

    def store(self, conn, records) -> int:
        for r in records:
            conn.execute(
                """INSERT INTO vulnerabilities(cve, vendor, product, name, description, date_added, due_date, in_kev,
                       ransomware_use, required_action, cwes)
                   VALUES (?,?,?,?,?,?,?,1,?,?,?)
                   ON CONFLICT(cve) DO UPDATE SET vendor=excluded.vendor, product=excluded.product,
                       name=excluded.name, description=excluded.description, date_added=excluded.date_added,
                       due_date=excluded.due_date, in_kev=1, ransomware_use=excluded.ransomware_use,
                       required_action=excluded.required_action,
                       cwes=CASE WHEN excluded.cwes='[]' THEN vulnerabilities.cwes ELSE excluded.cwes END""",
                (r["cve"], r["vendor"], r["product"], r["name"], r["description"], r["date_added"], r["due_date"],
                 r["ransomware_use"], r["required_action"], json.dumps(r["cwes"])))
            db.add_rel(conn, f"cve:{r['cve']}", "affects", product_node(r["vendor"], r["product"]), self.name)
            db.add_rel(conn, product_node(r["vendor"], r["product"]), "made-by", vendor_node(r["vendor"]), self.name)
        return len(records)
