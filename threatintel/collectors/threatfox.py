"""abuse.ch ThreatFox IOCs (C2 IPs, domains, URLs, hashes with malware family).

The anonymous JSON export now returns 410 Gone. The API
(POST https://threatfox-api.abuse.ch/api/v1/ {"query": "get_iocs", "days": N})
needs a free Auth-Key; set ABUSECH_AUTH_KEY to enable it.
"""
from __future__ import annotations

import json

from .. import aliases, db, defang, psl, timeutil
from .base import Collector

API = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatfoxCollector(Collector):
    name = "threatfox"
    title = "abuse.ch ThreatFox"
    homepage = "https://threatfox.abuse.ch/"
    licence = "CC0 1.0 (abuse.ch terms of use)"
    fixture_files = ("threatfox-iocs.json",)
    requires_env = "ABUSECH_AUTH_KEY"

    def fetch(self, conn=None):
        days = int(self.cfg.get("days", 3))
        res = self.get(API, method="POST", data={"query": "get_iocs", "days": days},
                       headers={"Auth-Key": self.env(self.requires_env)})
        return json.loads(res.body)

    def normalise(self, raw) -> list[dict]:
        out = []
        for r in raw.get("data") or []:
            ioc, kind = (r.get("ioc") or "").strip(), r.get("ioc_type", "")
            if not ioc:
                continue
            port = None
            if kind == "ip:port":
                ioc, _, port = ioc.rpartition(":")
                itype, value = "ip", ioc.strip("[]")
            elif kind == "domain":
                itype, value = "domain", defang.defang_domain(ioc.lower())
            elif kind == "url":
                itype, value = "url", defang.defang_url(defang.canonical_url(ioc))
            elif kind.endswith("_hash"):
                itype, value = "hash", ioc.lower()
            else:
                continue
            fam = r.get("malware_printable") or r.get("malware") or ""
            out.append({
                "type": itype, "value": value, "port": port,
                "malware": aliases.canonical_malware(r.get("malware") or fam) or None, "malware_display": fam,
                "threat_type": r.get("threat_type"), "confidence": r.get("confidence_level"),
                "tags": [t for t in (r.get("tags") or []) if t],
                "first_seen": timeutil.parse(r.get("first_seen")),
                "last_seen": timeutil.parse(r.get("last_seen")) or timeutil.parse(r.get("first_seen")),
                "reference": r.get("reference"),
            })
        return out

    def store(self, conn, records) -> int:
        for r in records:
            host = reg = None
            if r["type"] == "domain":
                reg = defang.defang_domain(psl.registered_domain(defang.refang(r["value"])))
            if r["type"] == "url":
                h = defang.url_host(r["value"])
                host = h if psl.is_ip(h) else defang.defang_domain(h)
                reg = psl.registered_domain(h) if psl.is_ip(h) else defang.defang_domain(psl.registered_domain(h))
            tags = [r["threat_type"] or "ioc"] + [f"tag:{t}" for t in r["tags"]]
            if r["threat_type"] == "botnet_cc":
                tags.append("c2")
            db.upsert_indicator(conn, type=r["type"], value=r["value"], source=self.name, first_seen=r["first_seen"],
                                last_seen=r["last_seen"], tags=tags, malware=r["malware"], host=host, reg_domain=reg,
                                extra={"port": r["port"], "confidence": r["confidence"], "malware": r["malware_display"],
                                       "reference": r["reference"]})
            if r["malware"]:
                rel = "c2-for" if r["threat_type"] == "botnet_cc" else "associated-with"
                db.add_rel(conn, f"{r['type']}:{r['value']}", rel, f"malware:{r['malware']}", self.name)
        return len(records)
