"""Defang / refang helpers and indicator type detection.

Malicious URLs and domains are stored and shown defanged so that nobody (and no
browser preview or chat client) follows them by accident:

    http://evil.example/login  ->  hxxp://evil[.]example/login

refang() reverses it for matching and for machine-readable exports.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from . import psl

HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I)
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)
TACTIC_RE = re.compile(r"^TA\d{4}$", re.I)
GROUP_RE = re.compile(r"^G\d{4}$", re.I)
SOFTWARE_RE = re.compile(r"^S\d{4}$", re.I)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$", re.I)


def refang(value: str) -> str:
    v = (value or "").strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.I)
    v = re.sub(r"^fxp", "ftp", v, flags=re.I)
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("[:]", ":"), ("[://]", "://"), ("[@]", "@")):
        v = v.replace(a, b)
    return v


def defang_domain(host: str) -> str:
    host = refang(host)
    return host.replace(".", "[.]")


def defang_url(url: str) -> str:
    url = refang(url)
    url = re.sub(r"^http", "hxxp", url, flags=re.I)
    url = re.sub(r"^ftp", "fxp", url, flags=re.I)
    try:
        parts = urlsplit(url)
    except ValueError:
        return url.replace(".", "[.]")
    host = parts.netloc
    if not host:
        return url.replace(".", "[.]")
    return url.replace(host, host.replace(".", "[.]"), 1)


def defang(value: str, kind: str | None = None) -> str:
    kind = kind or detect(value)
    if kind == "url":
        return defang_url(value)
    if kind == "domain":
        return defang_domain(value)
    return refang(value)


def url_host(url: str) -> str:
    """Host part of a (possibly defanged) URL, lower case, no port."""
    u = refang(url)
    if "://" not in u:
        u = "http://" + u
    try:
        host = urlsplit(u).hostname or ""
    except ValueError:
        host = ""
    return host.lower().strip(".")


def canonical_url(url: str) -> str:
    """Normalise a URL for matching: refang, lower-case scheme and host, keep path/query."""
    u = refang(url)
    if "://" not in u:
        u = "http://" + u
    try:
        p = urlsplit(u)
    except ValueError:
        return u
    netloc = (p.netloc or "").lower()
    path = p.path or "/"
    out = f"{p.scheme.lower()}://{netloc}{path}"
    if p.query:
        out += "?" + p.query
    return out


def detect(value: str) -> str:
    """Best-effort classification of a free-text search or IOC value."""
    v = refang(value).strip()
    if not v:
        return "empty"
    if CVE_RE.match(v):
        return "cve"
    if TACTIC_RE.match(v):
        return "tactic"
    if TECH_RE.match(v):
        return "technique"
    if GROUP_RE.match(v):
        return "attack-group"
    if SOFTWARE_RE.match(v):
        return "software"
    if re.match(r"^(?:https?|ftp)://", v, re.I):
        return "url"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if "/" in v:
        try:
            ipaddress.ip_network(v, strict=False)
            return "cidr"
        except ValueError:
            pass
    if HASH_RE.match(v):
        return "hash"
    if re.match(r"^AS\d+$", v, re.I):
        return "asn"
    if DOMAIN_RE.match(v) and psl.tld(v):
        if "/" in v:
            return "url"
        return "domain"
    if "/" in v and DOMAIN_RE.match(v.split("/")[0]):
        return "url"
    return "name"


def normalise_ioc(value: str) -> tuple[str, str]:
    """Return (type, stored value) as used in the indicators table."""
    kind = detect(value)
    v = refang(value).strip()
    if kind == "url":
        return "url", defang_url(canonical_url(v))
    if kind == "domain":
        return "domain", defang_domain(v.lower().strip("."))
    if kind == "ip":
        return "ip", str(ipaddress.ip_address(v))
    if kind == "cidr":
        return "cidr", str(ipaddress.ip_network(v, strict=False))
    if kind == "hash":
        return "hash", v.lower()
    return kind, v
