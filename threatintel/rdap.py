"""On-demand RDAP lookups: registration date, registrar and abuse contact.

Who is contacted
- data.iana.org for the RDAP bootstrap files (dns.json, ipv4.json, ipv6.json),
  cached for a week. They say which registry runs RDAP for a TLD or IP range.
- that registry's RDAP server (for example rdap.verisign.com for .com, or the
  RIRs rdap.arin.net / rdap.db.ripe.net for IPs). Only hosts named in the IANA
  bootstrap are allowed, also after redirects (ARIN hands RIPE space to RIPE).
- rdap.org, the public redirector, as a fallback when the bootstrap has no
  entry. Its redirect target must also be a bootstrap host.

Who is never contacted: the domain or IP being looked up. No DNS lookups of
suspicious names are made; the only names resolved are the registry servers.
Lookups go by registered domain (login.evil.example -> evil.example), so the
subdomain never leaves the machine. Results (including "not found") are cached
in the `rdap` table for `ttl_days`; registrar-level referrals are not followed.
"""
from __future__ import annotations

import ipaddress
import json
import threading
import time
from urllib.parse import quote, urlsplit

from . import config, db, defang, fetch, psl

BOOTSTRAP = {"dns": "https://data.iana.org/rdap/dns.json",
             "ipv4": "https://data.iana.org/rdap/ipv4.json",
             "ipv6": "https://data.iana.org/rdap/ipv6.json"}
FALLBACK = "https://rdap.org/{kind}/{value}"
TRANSPORT = None          # tests put an httpx.MockTransport here
_lock = threading.Lock()


def settings() -> dict:
    return {"ttl_days": 7, "host_interval_s": 2.0, "timeout_s": 15, "max_per_request": 8,
            **config.get().raw.get("rdap", {})}


# ------------------------------------------------------------------ what to look up

def target(value: str) -> tuple[str, str] | None:
    """Any IOC-ish value -> ("domain", registered domain) | ("ip", address) | None."""
    v = defang.refang(value or "").strip()
    kind = defang.detect(v)
    if kind == "url":
        v, kind = defang.url_host(v), defang.detect(defang.url_host(v))
    if kind == "ip":
        ip = ipaddress.ip_address(v)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast or ip.is_link_local:
            return None
        return "ip", str(ip)
    if kind == "domain":
        if psl.is_private_suffix(psl.public_suffix(v.lower())):
            return None   # site on a hosting platform (pages.dev, github.io): the registry knows nothing useful
        reg = psl.registered_domain(v.lower())
        return ("domain", reg) if reg and "." in reg else None
    return None


# ------------------------------------------------------------------ bootstrap

def _get(url: str, extra: set | None = None, **kw) -> bytes:
    s = settings()
    return fetch.get(url, feed="rdap", timeout_s=float(s["timeout_s"]), host_interval_s=float(s["host_interval_s"]),
                     transport=TRANSPORT, retries=1, backoff_s=3, extra_hosts=extra, max_bytes=2_000_000, **kw).body


def bootstrap(kind: str) -> dict:
    return json.loads(_get(BOOTSTRAP[kind], min_refetch_s=7 * 86400))


def _pick(urls: list[str]) -> str | None:
    https = [u for u in urls if u.startswith("https://")]
    return (https or [None])[0]


def registry_hosts() -> set[str]:
    hosts = set()
    for kind in BOOTSTRAP:
        try:
            for _, urls in bootstrap(kind).get("services", []):
                hosts |= {urlsplit(u).hostname for u in urls if urlsplit(u).hostname}
        except (fetch.FetchError, ValueError):
            continue
    return hosts


def service_for(kind: str, value: str) -> str | None:
    """Base RDAP URL for a domain's TLD or an IP's range, from the IANA bootstrap."""
    if kind == "domain":
        labels = value.split(".")
        services = bootstrap("dns").get("services", [])
        for i in range(len(labels)):          # longest suffix first (some entries are 2nd level)
            suffix = ".".join(labels[i:])
            for tlds, urls in services:
                if suffix in tlds:
                    return _pick(urls)
        return None
    ip = ipaddress.ip_address(value)
    best, best_len = None, -1
    for prefixes, urls in bootstrap("ipv4" if ip.version == 4 else "ipv6").get("services", []):
        for p in prefixes:
            net = ipaddress.ip_network(p, strict=False)
            if ip in net and net.prefixlen > best_len:
                best, best_len = _pick(urls), net.prefixlen
    return best


# ------------------------------------------------------------------ parsing

def _vcard(entity: dict, field: str) -> str | None:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] == field:
            v = item[3]
            return (v[0] if isinstance(v, list) else str(v)).replace("mailto:", "").replace("tel:", "") or None
    return None


def _walk_entities(entities, out=None):
    out = [] if out is None else out
    for e in entities or []:
        out.append(e)
        _walk_entities(e.get("entities"), out)
    return out


def parse(doc: dict, kind: str) -> dict:
    events = {e.get("eventAction"): e.get("eventDate") for e in doc.get("events") or []}
    ents = _walk_entities(doc.get("entities"))
    registrar = next((_vcard(e, "fn") for e in ents if "registrar" in (e.get("roles") or [])), None)
    abuse = next((e for e in ents if "abuse" in (e.get("roles") or [])), None)
    out = {"status": "ok", "registered": events.get("registration"), "expires": events.get("expiration"),
           "last_changed": events.get("last changed"), "registrar": registrar,
           "abuse_email": _vcard(abuse, "email") if abuse else None,
           "abuse_phone": _vcard(abuse, "tel") if abuse else None,
           "statuses": doc.get("status") or [], "country": doc.get("country"), "network": None}
    if kind == "ip":
        rng = f"{doc.get('startAddress', '')} - {doc.get('endAddress', '')}".strip(" -")
        out["network"] = " ".join(x for x in (doc.get("name"), doc.get("handle"), f"({rng})" if rng else "") if x)
        if not out["registrar"]:
            owner = next((e for e in ents if "registrant" in (e.get("roles") or [])), None)
            out["registrar"] = _vcard(owner, "fn") if owner else None   # for IPs: the holder of the block
    return out


# ------------------------------------------------------------------ lookup with cache

def cached(conn, value: str) -> dict | None:
    t = target(value)
    if not t:
        return None
    row = db.one(conn, "SELECT * FROM rdap WHERE key=?", (f"{t[0]}:{t[1]}",))
    if row:
        row["statuses"] = db.jload(row["statuses"])
    return row


def lookup(conn, value: str, *, refresh: bool = False, network: bool = True) -> dict | None:
    """Return the RDAP summary for a value, from cache or (if allowed) from the registry."""
    t = target(value)
    if not t:
        return None
    kind, q = t
    key = f"{kind}:{q}"
    row = cached(conn, value)
    ttl = float(settings()["ttl_days"]) * 86400
    if row and not refresh and time.time() - (row["fetched_at"] or 0) < ttl:
        return row
    if not network:
        return row
    with _lock:   # one lookup at a time keeps us polite to the registries
        res = _query(kind, q)
    res.update(key=key, kind=kind, query=q, fetched_at=time.time())
    conn.execute("""INSERT OR REPLACE INTO rdap(key, kind, query, status, registered, expires, last_changed, registrar,
                    abuse_email, abuse_phone, network, country, statuses, server, error, fetched_at)
                    VALUES (:key,:kind,:query,:status,:registered,:expires,:last_changed,:registrar,:abuse_email,
                    :abuse_phone,:network,:country,:statuses,:server,:error,:fetched_at)""",
                 {**{k: None for k in ("registered", "expires", "last_changed", "registrar", "abuse_email",
                                       "abuse_phone", "network", "country", "server", "error")},
                  **res, "statuses": json.dumps(res.get("statuses") or [])})
    conn.commit()
    return cached(conn, value)


def _query(kind: str, q: str) -> dict:
    path = "domain" if kind == "domain" else "ip"
    try:
        allowed = registry_hosts()
        base = service_for(kind, q)
    except (fetch.FetchError, ValueError) as exc:
        return {"status": "error", "error": f"bootstrap unavailable: {exc}"[:300]}
    url = f"{base.rstrip('/')}/{path}/{quote(q)}" if base else FALLBACK.format(kind=path, value=quote(q))
    host = urlsplit(url).hostname or ""
    if host == q or host.endswith("." + q):
        return {"status": "error", "error": "refusing: RDAP server is the queried host"}
    try:
        doc = json.loads(_get(url, extra=allowed, headers={"Accept": "application/rdap+json"}))
    except fetch.FetchError as exc:
        if exc.status == 404:
            return {"status": "not-found" if base else "no-service", "server": host}
        return {"status": "error", "error": str(exc)[:300], "server": host}
    except ValueError as exc:
        return {"status": "error", "error": f"bad JSON: {exc}"[:300], "server": host}
    out = parse(doc, kind)
    out["server"] = host
    return out


def lookup_many(conn, values: list[str], *, network: bool = True, limit: int | None = None) -> dict[str, dict]:
    """Look up several values, at most `limit` (default max_per_request) over the network."""
    limit = int(settings()["max_per_request"]) if limit is None else limit
    out, net_used = {}, 0
    for v in values:
        t = target(v)
        if not t or f"{t[0]}:{t[1]}" in out:
            continue
        key = f"{t[0]}:{t[1]}"
        row = cached(conn, v)
        fresh = row and time.time() - (row["fetched_at"] or 0) < float(settings()["ttl_days"]) * 86400
        if not fresh and network and net_used < limit:
            row = lookup(conn, v)
            net_used += 1
        if row:
            out[key] = row
    return out


def summary(row: dict | None) -> dict | None:
    """The fields shown in search/enrich results."""
    if not row:
        return None
    return {k: row.get(k) for k in ("query", "status", "registered", "expires", "registrar", "abuse_email",
                                    "network", "country", "server", "fetched_at", "error")}
