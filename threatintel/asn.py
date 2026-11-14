"""Offline IP -> ASN / country lookups from an ip2asn TSV file.

File format (iptoasn.com): range_start  range_end  AS_number  country_code  AS_description
Ranges are loaded into two sorted integer lists per IP version and searched with
bisect, so a lookup is O(log n) and needs no network.

Lookup order: the full table in data/ip2asn/ (after `collect ip2asn`), otherwise
the small subset bundled in fixtures/.
"""
from __future__ import annotations

import bisect
import ipaddress
import threading
from pathlib import Path

from . import config
from .config import FIXTURES

_lock = threading.Lock()
_table: dict | None = None


def data_file() -> Path:
    return config.get().db_path.parent / "ip2asn" / "ip2asn-combined.tsv"


def _source() -> Path | None:
    for p in (data_file(), FIXTURES / "ip2asn-subset.tsv"):
        if p.exists():
            return p
    return None


def _load() -> dict:
    tab = {4: ([], [], []), 6: ([], [], [])}   # starts, ends, payloads
    src = _source()
    if not src:
        return tab
    rows = {4: [], 6: []}
    with open(src, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 5:
                continue
            try:
                a, b = ipaddress.ip_address(parts[0]), ipaddress.ip_address(parts[1])
            except ValueError:
                continue
            asn = int(parts[2]) if parts[2].isdigit() else 0
            if asn == 0:
                continue  # "Not routed"
            rows[a.version].append((int(a), int(b), (asn, parts[3], parts[4])))
    for v in (4, 6):
        rows[v].sort()
        tab[v] = ([r[0] for r in rows[v]], [r[1] for r in rows[v]], [r[2] for r in rows[v]])
    return tab


def reload() -> int:
    global _table
    with _lock:
        _table = _load()
        return len(_table[4][0]) + len(_table[6][0])


def lookup(ip: str) -> dict | None:
    """{'asn': 14061, 'country': 'US', 'as_name': 'DIGITALOCEAN-ASN'} or None."""
    global _table
    if _table is None:
        reload()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    starts, ends, payloads = _table[addr.version]
    i = bisect.bisect_right(starts, int(addr)) - 1
    if i >= 0 and int(addr) <= ends[i]:
        asn, cc, name = payloads[i]
        return {"asn": asn, "country": cc if cc not in ("None", "") else None, "as_name": name}
    return None


def size() -> int:
    if _table is None:
        reload()
    return len(_table[4][0]) + len(_table[6][0])
