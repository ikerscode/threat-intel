"""AlienVault OTX pulses (optional, needs a free OTX key).

Checked 2026-11-14: /api/v1/pulses/subscribed and /api/v1/pulses/activity both
answer 403 "Authentication required" without a key, so this feed is skipped
unless OTX_API_KEY is set (environment or `python -m threatintel set-key
OTX_API_KEY`, which stores it in the desktop keyring, never in a file).

With a key it pulls the pulses modified in the last `days` days from the
account's subscriptions (OTX subscribes new accounts to AlienVault's own pulses)
and keeps up to `ioc_limit` indicators per pulse.
"""
from __future__ import annotations

import json
import time

from .. import aliases, db, defang, psl, timeutil
from .base import Collector

API = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit={limit}&modified_since={since}"
TYPE_MAP = {"IPv4": "ip", "IPv6": "ip", "domain": "domain", "hostname": "domain", "URL": "url",
            "FileHash-MD5": "hash", "FileHash-SHA1": "hash", "FileHash-SHA256": "hash"}


class OtxCollector(Collector):
    name = "otx"
    title = "AlienVault OTX pulses"
    homepage = "https://otx.alienvault.com/"
    licence = "OTX terms of service (free account); pulse content belongs to its authors"
    fixture_files = ("otx-pulses.json",)
    requires_env = "OTX_API_KEY"

    def fetch(self, conn=None):
        since = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - int(self.cfg.get("days", 3)) * 86400))
        res = self.get(API.format(limit=int(self.cfg.get("pulses", 20)), since=since),
                       headers={"X-OTX-API-KEY": self.env(self.requires_env)}, max_bytes=20_000_000)
        return json.loads(res.body)

    def normalise(self, raw) -> list[dict]:
        cap = int(self.cfg.get("ioc_limit", 200))
        out = []
        for p in raw.get("results") or []:
            fams = [aliases.canonical_malware(m.get("display_name") or m.get("id") or "")
                    for m in p.get("malware_families") or [] if isinstance(m, dict)]
            fams = [f for f in fams if f]
            for ind in (p.get("indicators") or [])[:cap]:
                itype = TYPE_MAP.get(ind.get("type"))
                value = (ind.get("indicator") or "").strip()
                if not itype or not value:
                    continue
                itype, stored = defang.normalise_ioc(value) if itype != "domain" else ("domain", defang.defang_domain(value.lower()))
                if itype not in ("ip", "domain", "url", "hash"):
                    continue
                out.append({"type": itype, "value": stored, "pulse": p.get("id"), "pulse_name": (p.get("name") or "")[:120],
                            "malware": fams[0] if fams else None, "adversary": p.get("adversary") or None,
                            "first_seen": timeutil.parse(ind.get("created")) or timeutil.parse(p.get("created")),
                            "last_seen": timeutil.parse(p.get("modified"))})
        return out

    def store(self, conn, records) -> int:
        for r in records:
            reg = None
            if r["type"] == "domain":
                reg = defang.defang_domain(psl.registered_domain(defang.refang(r["value"])))
            db.upsert_indicator(conn, type=r["type"], value=r["value"], source=self.name, first_seen=r["first_seen"],
                                last_seen=r["last_seen"], tags=["otx-pulse"], malware=r["malware"], reg_domain=reg,
                                extra={"pulse": r["pulse"], "pulse_name": r["pulse_name"], "adversary": r["adversary"]})
            if r["malware"]:
                db.add_rel(conn, f"{r['type']}:{r['value']}", "associated-with", f"malware:{r['malware']}", self.name)
        return len(records)
