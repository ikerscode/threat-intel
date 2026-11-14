"""Small public-suffix-aware domain splitter.

Implements the Public Suffix List algorithm (https://publicsuffix.org/list/):
normal rules, wildcard rules (*.ck) and exception rules (!www.ck), with the
implicit "*" default rule. The bundled list is a trimmed copy (see the header of
resources/public_suffix_trimmed.dat), so very deep geographic suffixes such as
city.state.us are not known and fall back to the parent rule.

    split("login.secure.paypal.co.uk") -> ("login.secure", "paypal", "co.uk")
    registered_domain("x.y.pages.dev") -> "y.pages.dev"
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache

from .config import RESOURCES

PSL_FILE = RESOURCES / "public_suffix_trimmed.dat"


@lru_cache(maxsize=1)
def _rules() -> tuple[frozenset, frozenset, frozenset, frozenset]:
    """Return (normal, wildcard, exception, private) rule sets."""
    normal, wildcard, exception, private = set(), set(), set(), set()
    section = "icann"
    for line in PSL_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if "BEGIN PRIVATE" in line:
            section = "private"
        if not line or line.startswith("//"):
            continue
        rule = line.split()[0].lower()
        if rule.startswith("!"):
            exception.add(rule[1:])
        elif rule.startswith("*."):
            wildcard.add(rule[2:])
        else:
            normal.add(rule)
        if section == "private":
            private.add(rule.lstrip("!*."))
    return frozenset(normal), frozenset(wildcard), frozenset(exception), frozenset(private)


def clean_host(host: str) -> str:
    host = (host or "").strip().strip(".").lower()
    host = host.replace("[.]", ".").replace("(.)", ".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host.split(":")[0] if host.count(":") == 1 else host


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def public_suffix(host: str) -> str:
    """Longest matching public suffix for host (falls back to the last label)."""
    host = clean_host(host)
    if not host or is_ip(host):
        return ""
    labels = host.split(".")
    normal, wildcard, exception, _ = _rules()
    best = labels[-1]  # implicit "*" rule
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in exception:
            # exception rule: suffix is the candidate minus its first label
            return ".".join(labels[i + 1:])
        if candidate in normal:
            best = candidate if len(candidate) > len(best) else best
            break
        parent = ".".join(labels[i + 1:])
        if parent and parent in wildcard:
            best = candidate if len(candidate) > len(best) else best
            break
    return best


def split(host: str) -> tuple[str, str, str]:
    """(subdomain, domain label, suffix). For IPs returns ("", ip, "")."""
    host = clean_host(host)
    if is_ip(host):
        return "", host, ""
    suffix = public_suffix(host)
    if not suffix or host == suffix:
        return "", "", suffix or host
    rest = host[: -len(suffix) - 1]
    parts = rest.split(".")
    return ".".join(parts[:-1]), parts[-1], suffix


def registered_domain(host: str) -> str:
    """eTLD+1, e.g. "paypal.co.uk". Empty string if the host is itself a suffix."""
    host = clean_host(host)
    if is_ip(host):
        return host
    _, dom, suffix = split(host)
    return f"{dom}.{suffix}" if dom else ""


def is_private_suffix(suffix: str) -> bool:
    """True when the suffix comes from the PSL private section (hosting platforms)."""
    return suffix in _rules()[3]


def tld(host: str) -> str:
    host = clean_host(host)
    return "" if is_ip(host) else host.rsplit(".", 1)[-1]
