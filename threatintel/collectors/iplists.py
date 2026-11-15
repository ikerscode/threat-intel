"""Plain-text IP reputation lists: Emerging Threats, CINS Army, blocklist.de.

All three publish one IP address per line with no other fields, so they share
one parser. They describe hosts seen attacking or scanning (brute force,
exploitation attempts, compromised machines), not C2 servers, so each carries a
moderate source weight and only reaches a "malicious" verdict when another feed
agrees (see scoring.SOURCE_WEIGHTS).

Lists can be large (CINS has about 15 000 entries, blocklist.de "all" about
23 000), so `limit` in config/feeds.toml caps the rows kept with a stable
hash-based sample, and `retention_days` prunes entries that left the list.
"""
from __future__ import annotations

import ipaddress

from .. import db
from .base import Collector, comment_lines, stable_sample


class IpListCollector(Collector):
    url: str = ""
    tags: tuple[str, ...] = ()
    default_limit = 5000

    def source_url(self) -> str:
        return self.url

    def fetch(self, conn=None):
        return self.get(self.source_url()).body.decode("utf-8", "replace")

    def normalise(self, raw: str) -> list[dict]:
        ips = []
        for line in comment_lines(raw):
            try:
                ip = ipaddress.ip_address(line.split()[0])
            except ValueError:
                continue
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast:
                continue  # never let a list mark our own lab ranges as hostile
            ips.append(str(ip))
        self.listed = len(set(ips))
        return [{"ip": ip} for ip in stable_sample(ips, int(self.cfg.get("limit", self.default_limit)))]

    def store(self, conn, records) -> int:
        ts = db.now()
        tags = list(self.tags)
        for r in records:
            db.upsert_indicator(conn, type="ip", value=r["ip"], source=self.name, first_seen=ts, last_seen=ts,
                                tags=tags)
        # how much of the list the sample kept (shown in the brief and README)
        db.set_meta(conn, f"listed:{self.name}", {"listed": getattr(self, "listed", len(records)), "kept": len(records)})
        return len(records)


class EtCompromisedCollector(IpListCollector):
    name = "et_compromised"
    title = "Emerging Threats compromised IPs"
    homepage = "https://rules.emergingthreats.net/blockrules/"
    licence = "Proofpoint ET Open block list, free to use (ET Open terms)"
    fixture_files = ("et-compromised-ips.txt",)
    url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    tags = ("compromised-host", "reputation")


class CinsCollector(IpListCollector):
    name = "cins"
    title = "CINS Army list"
    homepage = "https://cinsscore.com/"
    licence = "Free public list from Sentinel IPS / CINS (no redistribution terms published in the file)"
    fixture_files = ("cins-badguys.txt",)
    url = "https://cinsscore.com/list/ci-badguys.txt"
    tags = ("bad-reputation", "reputation")


class BlocklistDeCollector(IpListCollector):
    """blocklist.de fail2ban reports. `list = "ssh"` (default) or "all" in feeds.toml.

    The ssh list is the one that matters for the lab's SSH honeypot (honeypot-net
    on 2222): attackers it sees can be enriched against it.
    """
    name = "blocklistde"
    title = "blocklist.de attackers"
    homepage = "https://www.blocklist.de/en/export.html"
    licence = "Free service; blocklist.de asks for fair use and attribution"
    fixture_files = ("blocklistde-ssh.txt",)
    LISTS = {"ssh": "https://lists.blocklist.de/lists/ssh.txt", "all": "https://lists.blocklist.de/lists/all.txt"}

    def source_url(self) -> str:
        return self.LISTS.get(self.cfg.get("list", "ssh"), self.LISTS["ssh"])

    @property
    def tags(self):  # type: ignore[override]
        which = self.cfg.get("list", "ssh")
        return ("attacker", "bruteforce:ssh" if which == "ssh" else "attacker:any-service", "reputation")
