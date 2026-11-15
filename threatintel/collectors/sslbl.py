"""abuse.ch SSLBL: SHA-1 fingerprints of TLS certificates used by botnet C2 servers.

Source: https://sslbl.abuse.ch/blacklist/sslblacklist.csv (CC0, no key).
Format: "Listingdate,SHA1,Listingreason", for example
    2026-11-14 08:31:41,0038c1179510d131864264eb4a4a6648e8c54425,Vidar C&C

The SSLBL *IP* blacklist (sslipblacklist.csv) was deprecated on 2025-01-03 and
is empty; the JA3 list was last updated in 2021. The certificate list is still
updated daily, gives a malware family per entry, and a listing date, so it is
the SSLBL product this collector uses. Fingerprints are stored as type "hash"
with the tag "x509-sha1" (the STIX export writes an x509-certificate pattern for
them, not a file hash).
"""
from __future__ import annotations

import csv
import io
import re

from .. import aliases, db, timeutil
from .base import Collector

URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
SHA1 = re.compile(r"^[a-f0-9]{40}$")


class SslblCollector(Collector):
    name = "sslbl"
    title = "abuse.ch SSLBL certificate blacklist"
    homepage = "https://sslbl.abuse.ch/"
    licence = "CC0 1.0 (abuse.ch terms of use)"
    fixture_files = ("sslbl-certs.csv",)

    def fetch(self, conn=None):
        return self.get(URL).body.decode("utf-8", "replace")

    def normalise(self, raw: str) -> list[dict]:
        rows, seen = [], set()
        lines = [ln for ln in raw.splitlines() if ln.strip() and not ln.startswith("#")]
        for rec in csv.reader(io.StringIO("\n".join(lines))):
            if len(rec) < 3:
                continue
            when, sha1, reason = rec[0].strip(), rec[1].strip().lower(), rec[2].strip()
            if not SHA1.match(sha1) or sha1 in seen:
                continue
            seen.add(sha1)
            fam = re.sub(r"\s+C&C$", "", reason, flags=re.I).strip()
            generic = fam.lower() in ("malware", "")
            rows.append({"sha1": sha1, "listed": timeutil.parse(when), "reason": reason,
                         "malware_display": None if generic else fam,
                         "malware": None if generic else (aliases.canonical_malware(fam) or None)})
        rows.sort(key=lambda r: r["listed"] or 0, reverse=True)   # newest first, then cap
        return rows[: int(self.cfg.get("limit", 1500))]

    def store(self, conn, records) -> int:
        for r in records:
            db.upsert_indicator(conn, type="hash", value=r["sha1"], source=self.name, first_seen=r["listed"],
                                last_seen=r["listed"], tags=["x509-sha1", "c2-certificate"], malware=r["malware"],
                                extra={"reason": r["reason"], "malware": r["malware_display"]})
            if r["malware"]:
                db.add_rel(conn, f"hash:{r['sha1']}", "c2-cert-for", f"malware:{r['malware']}", self.name)
        return len(records)
