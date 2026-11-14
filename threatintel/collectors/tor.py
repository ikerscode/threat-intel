"""Tor Project bulk exit list.

Tor exits are tagged as context ("tor-exit"), not as malicious: plenty of
legitimate traffic leaves through Tor. These sightings carry zero weight in
indicator confidence; they only explain why an IP shows up.
"""
from __future__ import annotations

import ipaddress

from .. import db
from .base import Collector

URL = "https://check.torproject.org/torbulkexitlist"


class TorCollector(Collector):
    name = "tor"
    title = "Tor bulk exit list"
    homepage = "https://check.torproject.org/"
    licence = "Public data published by the Tor Project"
    fixture_files = ("tor-exits.txt",)
    context_only = True

    def fetch(self, conn=None):
        return self.get(URL).body.decode("utf-8", "replace")

    def normalise(self, raw: str) -> list[dict]:
        out = []
        for line in raw.splitlines():
            line = line.strip()
            try:
                out.append({"ip": str(ipaddress.ip_address(line))})
            except ValueError:
                continue
        return out

    def store(self, conn, records) -> int:
        ts = db.now()
        for r in records:
            db.upsert_indicator(conn, type="ip", value=r["ip"], source=self.name, first_seen=ts, last_seen=ts,
                                tags=["tor-exit"])
        return len(records)
