"""Hardening for a dashboard that is only meant to be reached from this machine.

Binding to 127.0.0.1 is not enough on its own. Any web page open in the same
browser can still send requests to localhost, and a DNS-rebinding page can even
read the answers. This middleware closes those gaps:

* Host allowlist: requests whose Host header is not a local name are refused,
  which defeats DNS rebinding (the attacker's hostname never matches).
* Cross-site write block: POST/PUT/PATCH/DELETE coming from another site
  (Sec-Fetch-Site or Origin says so) are refused, which stops CSRF.
* Security headers on every response, including a strict Content-Security-Policy
  so injected markup cannot run script even if an escape is ever missed.

Extra host names (e.g. a Docker service name) can be allowed with the
SECLAB_ALLOWED_HOSTS environment variable, comma separated.
"""
from __future__ import annotations

import os
from urllib.parse import urlsplit

DEFAULT_HOSTS = {"127.0.0.1", "localhost", "::1"}
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
SECURITY_HEADERS = [
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"cache-control", b"no-store"),
]


def allowed_hosts() -> set[str]:
    extra = os.environ.get("SECLAB_ALLOWED_HOSTS", "")
    return DEFAULT_HOSTS | {h.strip().lower() for h in extra.split(",") if h.strip()}


def _hostname(value: str) -> str:
    """Host header or Origin -> bare lowercase host name without port."""
    value = value.strip().lower()
    if "://" in value:
        return (urlsplit(value).hostname or "").lower()
    if value.startswith("["):  # [::1]:8101
        return value[1:value.find("]")] if "]" in value else value
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


class LocalGuard:
    """Pure ASGI middleware; add with app.add_middleware(LocalGuard)."""

    def __init__(self, app, hosts: set[str] | None = None):
        self.app = app
        self.hosts = hosts or allowed_hosts()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        reason = self._reject_reason(scope.get("method", "GET"), headers)
        if reason:
            body = ('{"error":"%s"}' % reason).encode()
            await send({"type": "http.response.start", "status": 403,
                        "headers": [(b"content-type", b"application/json"), *SECURITY_HEADERS]})
            return await send({"type": "http.response.body", "body": body})

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                existing = {k.lower() for k, _ in message.get("headers", [])}
                message["headers"] = list(message.get("headers", [])) + [
                    h for h in SECURITY_HEADERS if h[0] not in existing]
            await send(message)

        return await self.app(scope, receive, send_with_headers)

    def _reject_reason(self, method: str, headers: dict) -> str | None:
        if _hostname(headers.get("host", "")) not in self.hosts:
            return "host not allowed"
        if method.upper() in UNSAFE_METHODS:
            site = headers.get("sec-fetch-site", "").lower()
            if site and site not in ("same-origin", "none"):
                return "cross-site request blocked"
            origin = headers.get("origin")
            if origin and origin != "null" and _hostname(origin) not in self.hosts:
                return "cross-origin request blocked"
            if origin == "null":
                return "cross-origin request blocked"
        return None
