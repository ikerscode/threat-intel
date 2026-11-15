"""Polite HTTP fetcher used by every collector.

What it does for each request:
- refuses any host that is not on FEED_HOSTS. The phishing and malware URLs we
  collect are data, never destinations; this allowlist makes it impossible for a
  bug elsewhere to fetch one of them.
- sends the generic User-Agent from the config (no personal details).
- keeps an on-disk cache per URL (body + metadata). If the cached copy is younger
  than `min_refetch_s` it is returned without touching the network.
- sends If-None-Match / If-Modified-Since when the cache has an ETag or
  Last-Modified and treats 304 as "use the cache".
- enforces a minimum gap between requests to the same host.
- optionally refuses bodies larger than `max_bytes` (streamed, so an oversized
  file is never read in full) and lets a collector `transform` the body before
  it is cached (CIRCL events drop embedded attachments that way).
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from . import config

# Hosts the collectors are allowed to contact. Nothing else is ever requested.
FEED_HOSTS = {
    "www.cisa.gov",
    "api.first.org",
    "services.nvd.nist.gov",
    "raw.githubusercontent.com",
    "feodotracker.abuse.ch",
    "urlhaus-api.abuse.ch",
    "threatfox-api.abuse.ch",
    "openphish.com",
    "api.ransomware.live",
    "www.spamhaus.org",
    "check.torproject.org",
    "iptoasn.com",
    "sslbl.abuse.ch",
    "rules.emergingthreats.net",
    "cinsscore.com",
    "lists.blocklist.de",
    "phishing.army",
    "www.circl.lu",
    "otx.alienvault.com",
    # RDAP: the IANA bootstrap files and the rdap.org redirector. The registry
    # RDAP servers themselves are allowed per request by rdap.py, using only the
    # hosts that the IANA bootstrap lists (never the host being looked up).
    "data.iana.org",
    "rdap.org",
}


class FetchError(RuntimeError):
    def __init__(self, msg: str, status: int | None = None):
        super().__init__(msg)
        self.status = status


@dataclass
class FetchResult:
    url: str
    body: bytes
    status: int          # HTTP status, or 0 when served from cache without a request
    from_cache: bool
    fetched_at: float
    note: str = ""       # e.g. "stale cache after network error"


_host_lock = threading.Lock()
_last_request: dict[str, float] = {}


def _cache_paths(cache_dir: Path, feed: str, key: str) -> tuple[Path, Path]:
    h = hashlib.sha1(key.encode()).hexdigest()[:20]
    d = cache_dir / feed
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{h}.body", d / f"{h}.meta.json"


def _wait_for_host(host: str, interval: float) -> None:
    """Sleep until `interval` seconds have passed since the last request to host."""
    while True:
        with _host_lock:
            last = _last_request.get(host, 0.0)
            wait = last + interval - time.monotonic()
            if wait <= 0:
                _last_request[host] = time.monotonic()
                return
        time.sleep(min(wait, 5))


def check_host(url: str, extra_hosts: frozenset | set | None = None) -> str:
    host = (urlsplit(url).hostname or "").lower()
    if host not in FEED_HOSTS and host not in (extra_hosts or ()):
        raise FetchError(f"refusing to contact non-feed host {host!r}")
    return host


def _read_capped(client: httpx.Client, method: str, url: str, headers: dict, data, max_bytes: int) -> httpx.Response:
    """Send a request but stop reading once the body passes max_bytes."""
    req = client.build_request(method, url, headers=headers, json=data if method == "POST" else None)
    resp = client.send(req, stream=True)
    try:
        declared = int(resp.headers.get("content-length") or 0)
        if declared > max_bytes:
            raise FetchError(f"{url} is {declared} bytes, over the {max_bytes} byte cap", status=resp.status_code)
        chunks, size = [], 0
        for chunk in resp.iter_bytes():
            size += len(chunk)
            if size > max_bytes:
                raise FetchError(f"{url} passed the {max_bytes} byte cap while downloading", status=resp.status_code)
            chunks.append(chunk)
        resp._content = b"".join(chunks)
    finally:
        resp.close()
    return resp


def get(url: str, *, feed: str, min_refetch_s: float = 0, timeout_s: float = 30,
        host_interval_s: float | None = None, headers: dict | None = None,
        method: str = "GET", data: dict | None = None, cache_key: str | None = None,
        transport: httpx.BaseTransport | None = None, retries: int = 2,
        backoff_s: float = 10.0, extra_hosts: frozenset | set | None = None,
        max_bytes: int | None = None, transform=None) -> FetchResult:
    """Fetch a feed URL with caching and conditional requests.

    extra_hosts  hosts allowed for this request only (RDAP registry servers)
    max_bytes    refuse larger bodies (checked on Content-Length and while streaming)
    transform    function bytes -> bytes applied before the body is cached and returned
    """
    settings = config.get()
    host = check_host(url, extra_hosts)
    key = cache_key or f"{method} {url} {json.dumps(data, sort_keys=True) if data else ''}"
    body_path, meta_path = _cache_paths(settings.cache_dir, feed, key)
    meta = json.loads(meta_path.read_text()) if meta_path.exists() and body_path.exists() else None

    if meta and min_refetch_s and time.time() - meta.get("fetched_at", 0) < min_refetch_s:
        return FetchResult(url, body_path.read_bytes(), 0, True, meta["fetched_at"], note="fresh cache")

    req_headers = {"User-Agent": settings.user_agent, "Accept-Encoding": "gzip"}
    if meta and method == "GET":
        if meta.get("etag"):
            req_headers["If-None-Match"] = meta["etag"]
        if meta.get("last_modified"):
            req_headers["If-Modified-Since"] = meta["last_modified"]
    req_headers.update(headers or {})

    interval = host_interval_s if host_interval_s is not None else settings.default_host_interval_s
    try:
        for attempt in range(retries + 1):
            _wait_for_host(host, interval)
            with httpx.Client(timeout=timeout_s, follow_redirects=True, transport=transport,
                              event_hooks={"request": [lambda r: check_host(str(r.url), extra_hosts)]}) as client:
                # The request hook checks every hop, so a redirect off the allowlist is never sent.
                if max_bytes:
                    resp = _read_capped(client, method, url, req_headers, data, max_bytes)
                elif method == "POST":
                    resp = client.post(url, headers=req_headers, json=data)
                else:
                    resp = client.get(url, headers=req_headers)
                check_host(str(resp.url), extra_hosts)
            # Back off on rate limiting and temporary server errors, then try again.
            if resp.status_code in (429, 500, 502, 503, 504) and attempt < retries:
                time.sleep(backoff_s * (attempt + 1))
                continue
            break
    except httpx.HTTPError as exc:
        if meta:
            # Network trouble: fall back to the last good copy rather than failing the run.
            return FetchResult(url, body_path.read_bytes(), 0, True, meta["fetched_at"],
                               note=f"network error, used stale cache: {exc}")
        raise FetchError(f"{type(exc).__name__}: {exc}") from exc

    if resp.status_code == 304 and meta:
        meta["fetched_at"] = time.time()
        meta_path.write_text(json.dumps(meta))
        return FetchResult(url, body_path.read_bytes(), 304, True, meta["fetched_at"], note="304 not modified")
    if resp.status_code >= 400:
        raise FetchError(f"HTTP {resp.status_code} from {host}: {resp.text[:200]}", status=resp.status_code)

    body = resp.content
    if transform is not None:
        body = transform(body)
    body_path.write_bytes(body)
    meta = {
        "url": url,
        "status": resp.status_code,
        "etag": resp.headers.get("etag"),
        "last_modified": resp.headers.get("last-modified"),
        "fetched_at": time.time(),
        "bytes": len(body),
    }
    meta_path.write_text(json.dumps(meta))
    return FetchResult(url, body, resp.status_code, False, meta["fetched_at"])
