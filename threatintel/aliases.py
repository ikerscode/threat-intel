"""Name normalisation and alias resolution for groups and malware families.

Feeds spell the same thing many ways: "LockBit 3.0", "lockbit3", "LockBit Black",
"win.lockbit". norm() reduces a name to a comparison key and canonical() maps
that key through the curated table in config/aliases.toml.
"""
from __future__ import annotations

import re
import tomllib
from functools import lru_cache

from .config import ROOT

ALIAS_FILE = ROOT / "config" / "aliases.toml"

# Trailing words that carry no identity ("Vexy Ransomware" == "vexy").
SUFFIXES = ("ransomware", "ransom", "group", "team", "gang", "crew", "operators")
# Malpedia-style platform prefixes used by ThreatFox ("win.cobalt_strike").
PLATFORM_PREFIX = re.compile(r"^(win|elf|osx|apk|js|ps1|vbs|py|jar|php|asp|sh|unknown)\.", re.I)


def norm(name: str | None) -> str:
    """Comparison key: lower case, alphanumerics only, without noise suffixes."""
    if not name:
        return ""
    s = PLATFORM_PREFIX.sub("", str(name).strip().lower())
    s = re.sub(r"[^a-z0-9]+", " ", s).strip()
    words = s.split()
    while len(words) > 1 and words[-1] in SUFFIXES:
        words.pop()
    key = "".join(words)
    # glued forms such as "incransom" or "vexyransomware"
    for suf in SUFFIXES:
        if key.endswith(suf) and len(key) - len(suf) >= 3:
            key = key[: -len(suf)]
            break
    return key


def strip_version(key: str) -> str:
    """'lockbit30' -> 'lockbit', 'lockbit3' -> 'lockbit' (used for software <-> group matching)."""
    stripped = re.sub(r"(v?\d+)+$", "", key)
    return stripped if len(stripped) >= 3 else key


@lru_cache(maxsize=1)
def _table() -> dict[str, dict[str, str]]:
    """{'groups': {alias_key: canonical_key}, 'malware': {...}, plus display names}."""
    data = tomllib.loads(ALIAS_FILE.read_text(encoding="utf-8")) if ALIAS_FILE.exists() else {}
    out: dict[str, dict[str, str]] = {}
    for section in ("groups", "malware"):
        mapping: dict[str, str] = {}
        display: dict[str, str] = {}
        for canon, alist in data.get(section, {}).items():
            ck = norm(canon)
            display[ck] = canon
            mapping[ck] = ck
            for a in alist:
                mapping.setdefault(norm(a), ck)
        out[section] = mapping
        out[section + "_display"] = display
    return out


def canonical_group(name: str | None) -> str:
    k = norm(name)
    return _table()["groups"].get(k, k)


def canonical_malware(name: str | None) -> str:
    k = norm(name)
    return _table()["malware"].get(k, k)


def display_name(key: str, section: str = "malware") -> str | None:
    return _table()[section + "_display"].get(key)


def curated_entries(section: str) -> dict[str, list[str]]:
    """Inverse view used by the HUD/README: canonical display -> alias keys."""
    tab = _table()
    disp = tab[section + "_display"]
    inv: dict[str, list[str]] = {}
    for alias, canon in tab[section].items():
        inv.setdefault(disp.get(canon, canon), []).append(alias)
    return inv


# URLhaus / ThreatFox tags that describe a file or platform, not a malware family.
GENERIC_TAGS = {
    "elf", "exe", "dll", "doc", "docx", "xls", "zip", "rar", "7z", "iso", "lnk", "js", "vbs", "hta", "ps1", "sh",
    "bat", "msi", "apk", "jar", "pdf", "html", "ascii", "encrypted", "opendir", "32bit", "64bit", "32-bit",
    "64-bit", "arm", "arm7", "arm5", "arm6", "mips", "mipsel", "x86", "x86_64", "i686", "m68k", "sparc", "ppc",
    "sh4", "powerpc", "botnet", "c2", "cc", "payload", "dropper", "loader", "malware", "stealer", "rat",
    "ransomware", "trojan", "miner", "github", "dropbox", "google", "discord", "telegram",
    "ua-wget", "wget", "curl", "censys", "shodan", "unknown", "none", "malicious", "phishing", "synthetic",
}


_GENERIC_KEYS = {norm(g) for g in GENERIC_TAGS}


def is_generic_tag(tag: str | None) -> bool:
    t = (tag or "").strip().lower()
    return not t or t in GENERIC_TAGS or norm(t) in _GENERIC_KEYS or len(norm(t)) < 3
