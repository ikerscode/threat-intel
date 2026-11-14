"""abuse.ch Feodo Tracker botnet C2 IP blocklist (JSON).

Source: https://feodotracker.abuse.ch/downloads/ipblocklist.json
Each row is a C2 server with its malware family (QakBot, Emotet, ...), port,
ASN and country. Data is CC0.
"""
from __future__ import annotations

import json

from .. import aliases, db, timeutil
from .base import Collector

URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


class FeodoCollector(Collector):
    name = "feodo"
    title = "abuse.ch Feodo Tracker"
    homepage = "https://feodotracker.abuse.ch/"
    licence = "CC0 1.0 (abuse.ch terms of use)"
    fixture_files = ("feodo-ipblocklist.json",)

    def fetch(self, conn=None):
        return json.loads(self.get(URL).body)

    def normalise(self, raw) -> list[dict]:
        out = []
        for r in raw:
            ip = (r.get("ip_address") or "").strip()
            if not ip:
                continue
            fam = r.get("malware") or ""
            out.append({
                "ip": ip, "port": r.get("port"), "status": r.get("status"),
                "malware_display": fam, "malware": aliases.canonical_malware(fam) or None,
                "asn": r.get("as_number"), "as_name": r.get("as_name"), "country": r.get("country"),
                "first_seen": timeutil.parse(r.get("first_seen")),
                "last_seen": timeutil.parse(r.get("last_online")) or timeutil.parse(r.get("first_seen")),
                "hostname": r.get("hostname"),
            })
        return out

    def store(self, conn, records) -> int:
        for r in records:
            ind = db.upsert_indicator(
                conn, type="ip", value=r["ip"], source=self.name, first_seen=r["first_seen"], last_seen=r["last_seen"],
                tags=["c2", "botnet-c2", f"status:{r['status']}"], malware=r["malware"], asn=r["asn"],
                as_name=r["as_name"], country=r["country"],
                extra={"port": r["port"], "malware": r["malware_display"], "hostname": r["hostname"]})
            if r["malware"]:
                db.add_rel(conn, f"ip:{r['ip']}", "c2-for", f"malware:{r['malware']}", self.name)
        return len(records)
