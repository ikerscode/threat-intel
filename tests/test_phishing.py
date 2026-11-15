"""Brand impersonation: tokens, edit distance, homoglyphs, punycode, score and reasons."""
import time

import pytest

from threatintel import phishing


@pytest.mark.parametrize("url,brand,method", [
    ("hxxp://secure-paypal-login[.]example/x", "paypal", "token"),
    ("http://paypalsecure.example/", "paypal", "label"),
    ("http://paypai-login.example/", "paypal", "lookalike"),
    ("http://xn--pypal-4ve.com/", "paypal", "homoglyph"),          # p<Cyrillic a>ypal
    ("http://xn--80ak6aa92e.com/", "apple", "homoglyph"),          # all-Cyrillic "apple"
    ("rnicrosoft-login.top", "microsoft", "homoglyph"),            # rn -> m
    ("http://g00gle.com.verify.xyz/a", "google", "homoglyph"),     # 0 -> o
    ("http://metamsak-wallet.example/", "metamask", "lookalike"),  # adjacent swap
    ("http://evil.pages.dev/office365/login", "microsoft", "path"),
])
def test_brand_detection(url, brand, method):
    a = phishing.analyse(url)
    assert a["brands"][:1] == [brand], a
    assert a["method"] == method


@pytest.mark.parametrize("url", [
    "https://www.paypal.com/signin", "https://login.microsoftonline.com/", "http://purchase-now.example/",
    "http://looking-good.example/", "http://finance-news.example/", "http://cloudy.example/", "http://apply.example/",
])
def test_no_false_brand(url):
    assert phishing.analyse(url)["brands"] == []


def test_keyword_only_matcher_kept_for_comparison():
    assert phishing.keyword_brands("http://purchase.example/") == ["chase"]   # the old false positive
    assert phishing.analyse("http://purchase.example/")["brands"] == []


def test_score_reasons_add_up():
    now = time.time()
    a = phishing.analyse("http://secure-paypa1-account.verify.login.example.top/update",
                         registered=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 5 * 86400)), feeds=2, now=now)
    total = sum(int(r.split()[0]) for r in a["reasons"])
    assert a["score"] == min(100, total)
    text = " ".join(a["reasons"])
    for needle in ("paypal", "suspicious words", ".top", "registered 5 days ago", "2 phishing feeds"):
        assert needle in text


def test_idn_display_and_helpers():
    a = phishing.analyse("http://xn--80ak6aa92e.com/")
    assert a["idn"] and a["unicode_host"] != a["host"]
    assert phishing.skeleton("раураl") == "paypal"
    assert phishing.osa_distance("paypal", "papyal", 1) == 1
    assert phishing.osa_distance("paypal", "zzzzzz", 1) == 2  # early exit past the limit


def test_ip_host_and_hosting_signals():
    a = phishing.analyse("http://203.0.113.9/chase/login")
    assert a["is_ip_host"] and any("raw IP" in r for r in a["reasons"])
    b = phishing.analyse("https://my-site.weebly.com/")
    assert b["hosting"] == "weebly.com"


def test_seeded_phishing_analysis(conn):
    from threatintel import queries
    s = queries.phishing_analysis_summary(conn)
    op = s["by_source"]["openphish"]
    assert op["total"] >= 100 and 0 <= op["unbranded"] <= op["total"]
    assert s["by_type"]["domain"]["total"] > 0
    top = queries.phishing_top(conn, 5)
    assert top and top[0]["score"] >= top[-1]["score"] and top[0]["reasons"]
