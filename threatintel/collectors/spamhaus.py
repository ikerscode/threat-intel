"""Spamhaus DROP (Don't Route Or Peer) netblocks.

EDROP was merged into DROP in 2024 (edrop.txt now only carries a notice), so we
fetch the DROP JSON-lines files for IPv4 and IPv6. Netblocks go to the
`netblocks` table (used for IP-in-netblock checks) and to `indicators` as cidr.
"""
from __future__ import annotations

import ipaddress
import json

from .. import db
from .base import Collector

URLS = ("https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json")


class SpamhausCollector(Collector):
    name = "spamhaus"
    title = "Spamhaus DROP"
    homepage = "https://www.spamhaus.org/blocklists/do-not-route-or-peer/"
    licence = "Free for use in firewalls/routers; redistribution limited (Spamhaus DROP terms)"
    fixture_files = ("spamhaus-drop.jsonl",)

    def fetch(self, conn=None):
        return "\n".join(self.get(u).body.decode("utf-8", "replace") for u in URLS)

    def normalise(self, raw: str) -> list[dict]:
        out = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                # also accept the classic "1.2.3.0/24 ; SBL123" text format
                cidr, _, sbl = line.partition(";")
                obj = {"cidr": cidr.strip(), "sblid": sbl.strip()}
            if "cidr" not in obj:
                continue
            try:
                net = ipaddress.ip_network(obj["cidr"], strict=False)
            except ValueError:
                continue
            out.append({"cidr": str(net), "sbl": obj.get("sblid"), "rir": obj.get("rir"), "version": net.version,
                        "start": int(net.network_address), "end": int(net.broadcast_address)})
        return out

    def store(self, conn, records) -> int:
        ts = db.now()
        conn.execute("DELETE FROM netblocks WHERE list='drop'")
        for r in records:
            # integers are stored zero-padded as text so IPv6 ranges compare correctly
            conn.execute("""INSERT OR REPLACE INTO netblocks(cidr, list, sbl_id, rir, start_int, end_int, version, first_seen)
                            VALUES (?,?,?,?,?,?,?,?)""",
                         (r["cidr"], "drop", r["sbl"], r["rir"], f"{r['start']:039d}", f"{r['end']:039d}", r["version"], ts))
            db.upsert_indicator(conn, type="cidr", value=r["cidr"], source=self.name, tags=["drop", "hijacked-or-criminal-netblock"],
                                extra={"sbl": r["sbl"], "rir": r["rir"]})
        return len(records)
