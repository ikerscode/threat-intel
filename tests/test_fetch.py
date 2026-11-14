"""Polite fetcher: allowlist, cache, conditional requests (httpx MockTransport, no network)."""
import httpx
import pytest

from threatintel import fetch

URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


def test_refuses_non_feed_hosts():
    with pytest.raises(fetch.FetchError):
        fetch.get("http://phish.example/login", feed="t")


def test_etag_then_304_and_min_refetch():
    seen = []

    def handler(request):
        seen.append(dict(request.headers))
        if request.headers.get("if-none-match") == '"v1"':
            return httpx.Response(304)
        return httpx.Response(200, content=b"[1]", headers={"ETag": '"v1"'})

    t = httpx.MockTransport(handler)
    r1 = fetch.get(URL, feed="t-etag", transport=t, host_interval_s=0)
    assert r1.body == b"[1]" and not r1.from_cache
    assert seen[0]["user-agent"] == "seclab-ti/0.1"
    r2 = fetch.get(URL, feed="t-etag", transport=t, host_interval_s=0)
    assert r2.status == 304 and r2.from_cache and r2.body == b"[1]"
    r3 = fetch.get(URL, feed="t-etag", transport=t, host_interval_s=0, min_refetch_s=3600)
    assert r3.status == 0 and len(seen) == 2  # served from cache without a request


def test_redirect_off_allowlist_is_refused():
    def handler(request):
        if request.url.host == "openphish.com":
            return httpx.Response(302, headers={"Location": "https://evil.example/feed"})
        return httpx.Response(200, content=b"x")

    with pytest.raises(fetch.FetchError):
        fetch.get("https://openphish.com/feed.txt", feed="t-redir", transport=httpx.MockTransport(handler),
                  host_interval_s=0, retries=0)


def test_retries_on_503():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(503) if len(calls) == 1 else httpx.Response(200, content=b"ok")

    r = fetch.get("https://www.cisa.gov/x.json", feed="t-retry", transport=httpx.MockTransport(handler),
                  host_interval_s=0, backoff_s=0)
    assert r.body == b"ok" and len(calls) == 2
