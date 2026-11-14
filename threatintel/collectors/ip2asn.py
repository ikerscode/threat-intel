"""Optional offline IP -> ASN / country table from iptoasn.com (ip2asn-combined.tsv.gz).

The file (about 11 MB) is downloaded into the cache and copied to data/ip2asn/.
asn.py loads it for enrichment and clustering. Without it, ASN data still comes
from feeds that carry it (Feodo) and from the small fixture subset.
"""
from __future__ import annotations

import gzip
import shutil

from .. import asn
from .base import Collector

URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"


class Ip2asnCollector(Collector):
    name = "ip2asn"
    title = "iptoasn.com IP-to-ASN"
    homepage = "https://iptoasn.com/"
    licence = "Public Domain Dedication and License (PDDL) v1.0"
    fixture_files = ("ip2asn-subset.tsv",)

    def fetch(self, conn=None):
        return {"gz": self.get(URL).body}

    def load_fixture(self, fixture_dir):
        return {"path": fixture_dir / self.fixture_files[0]}

    def normalise(self, raw) -> dict:
        return raw

    def store(self, conn, rec) -> int:
        dest = asn.data_file()
        dest.parent.mkdir(parents=True, exist_ok=True)
        if "gz" in rec:
            dest.write_bytes(gzip.decompress(rec["gz"]))
            return asn.reload()
        src = rec["path"]
        if dest.exists() and dest.stat().st_size > 1_000_000:
            # never overwrite a full live table with the small fixture subset
            return asn.reload()
        else:
            shutil.copyfile(src, dest)
        return asn.reload()
