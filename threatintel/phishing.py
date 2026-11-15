"""Offline analysis of phishing URLs and domains: brand impersonation, TLDs, hosting, score.

Nothing here touches the network. A URL (or a bare domain) is split into host,
registered domain (psl.py) and path, then checked against the curated brand list
in config/brands.toml in four ways:

1. exact brand token in a host label           login-paypal-secure.example -> paypal
2. brand inside a longer label                  paypalsecure.example        -> paypal
3. edit distance (Damerau, OSA) <= 1 (<= 2 for terms of 9+ letters)
                                                paypai-login.example        -> paypal
4. homoglyph / character-swap folding: punycode labels are decoded (IDNA), the
   Unicode is reduced to a Latin "skeleton" (Cyrillic and Greek lookalikes,
   accents) and common swaps are folded (0->o, 1->l, 3->e, rn->m, vv->w)
                                                xn--pypal-4ve.example (pаypal with a Cyrillic a),
                                                rnicrosoft-login.example, g00gle.example

A brand is never reported when the registered domain is one the brand owns.
The result carries a 0-100 score with one reason per point added (formula in
scoring.PHISH_FORMULA). keyword_brands() keeps the old keyword-only matcher so
the HUD and brief can show the before/after unbranded rate.
"""
from __future__ import annotations

import re
import tomllib
import unicodedata
from functools import lru_cache
from urllib.parse import urlsplit

from . import defang, psl, timeutil
from .config import ROOT
from .scoring import PHISH_POINTS as P

BRAND_FILE = ROOT / "config" / "brands.toml"

# ------------------------------------------------------------------ legacy keyword matcher (kept for before/after)

LEGACY_KEYWORDS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "microsoft": (("microsoft", "office365", "office-365", "outlook", "onedrive", "sharepoint", "msonline", "hotmail", "live-login"),
                  ("microsoft.com", "office.com", "live.com", "outlook.com", "sharepoint.com", "microsoftonline.com")),
    "paypal": (("paypal", "paypa1"), ("paypal.com",)),
    "apple": (("apple", "icloud", "itunes", "appleid"), ("apple.com", "icloud.com")),
    "amazon": (("amazon", "amzn", "prime-video"), ("amazon.com", "amazon.co.uk", "amazon.de", "amazonaws.com")),
    "netflix": (("netflix", "nflx"), ("netflix.com",)),
    "meta": (("facebook", "instagram", "whatsapp", "meta-verify", "fb-login"), ("facebook.com", "instagram.com", "whatsapp.com", "meta.com")),
    "google": (("google", "gmail", "googledocs"), ("google.com", "gmail.com", "googleusercontent.com", "goo.gl")),
    "dhl": (("dhl",), ("dhl.com", "dhl.de")),
    "fedex": (("fedex",), ("fedex.com",)),
    "ups": (("ups-", "-ups", "upsdelivery"), ("ups.com",)),
    "usps": (("usps",), ("usps.com",)),
    "royal mail": (("royalmail", "royal-mail"), ("royalmail.com",)),
    "hmrc": (("hmrc", "gov-uk-refund"), ("gov.uk",)),
    "coinbase": (("coinbase",), ("coinbase.com",)),
    "binance": (("binance",), ("binance.com",)),
    "metamask": (("metamask",), ("metamask.io",)),
    "ledger": (("ledger-live", "ledgerwallet", "ledger-"), ("ledger.com",)),
    "trezor": (("trezor",), ("trezor.io",)),
    "steam": (("steamcommunity", "steampowered", "steam-"), ("steamcommunity.com", "steampowered.com")),
    "roblox": (("roblox",), ("roblox.com",)),
    "adobe": (("adobe",), ("adobe.com",)),
    "docusign": (("docusign",), ("docusign.com", "docusign.net")),
    "dropbox": (("dropbox",), ("dropbox.com",)),
    "linkedin": (("linkedin",), ("linkedin.com",)),
    "att": (("att-", "attmail", "att.net", "currently-att"), ("att.com", "att.net")),
    "verizon": (("verizon",), ("verizon.com",)),
    "chase": (("chase",), ("chase.com",)),
    "wells fargo": (("wellsfargo", "wells-fargo"), ("wellsfargo.com",)),
    "bank of america": (("bankofamerica", "bofa"), ("bankofamerica.com",)),
    "hsbc": (("hsbc",), ("hsbc.com", "hsbc.co.uk")),
    "santander": (("santander",), ("santander.com", "santander.co.uk")),
    "barclays": (("barclays",), ("barclays.co.uk", "barclays.com")),
    "lloyds": (("lloyds",), ("lloydsbank.com",)),
    "natwest": (("natwest",), ("natwest.com",)),
    "telegram": (("telegram",), ("telegram.org",)),
    "discord": (("discord",), ("discord.com", "discord.gg")),
    "booking.com": (("booking",), ("booking.com",)),
    "dpd": (("dpd",), ("dpd.co.uk", "dpd.com")),
    "evri": (("evri", "hermes"), ("evri.com",)),
    "allegro": (("allegro",), ("allegro.pl",)),
    "spotify": (("spotify",), ("spotify.com",)),
    "yahoo": (("yahoo",), ("yahoo.com",)),
    "aol": (("aol",), ("aol.com",)),
    "ebay": (("ebay",), ("ebay.com", "ebay.co.uk")),
    "walmart": (("walmart",), ("walmart.com",)),
    "irs": (("irs-", "irs.gov-"), ("irs.gov",)),
    "webmail (generic)": (("webmail", "roundcube", "zimbra", "owa-"), ()),
}
BRANDS = LEGACY_KEYWORDS  # old name, kept for importers


def keyword_brands(url: str) -> list[str]:
    """The original matcher: keyword substring anywhere in host+path."""
    real = defang.canonical_url(url)
    reg = psl.registered_domain(defang.url_host(real))
    haystack = re.sub(r"[^a-z0-9.\-/]", "", real.lower().split("://", 1)[-1])
    return [b for b, (kws, legit) in LEGACY_KEYWORDS.items() if reg not in legit and any(k in haystack for k in kws)]


# ------------------------------------------------------------------ reference data

# Registered domains that belong to free hosting / site builders (not in the PSL private section).
HOSTING_DOMAINS = {
    "weebly.com", "wordpress.com", "000webhostapp.com", "godaddysites.com", "jimdosite.com", "mystrikingly.com",
    "google.com", "googleapis.com", "ipfs.io", "dweb.link", "glitch.me", "webnode.page", "teachable.com",
    "canva.site", "gamma.site", "start.page", "wcomhost.com", "sharepoint.com", "office.com", "zohopublic.com",
    "typeform.com", "jotform.com", "forms.gle", "plesk.page", "ukit.me", "tilda.ws", "ucraft.site",
    "wixsite.com", "wix.com", "square.site", "webflow.io", "framer.app", "framer.website", "replit.app",
    "vercel.app", "netlify.app", "github.io", "firebaseapp.com", "web.app", "r2.dev", "workers.dev", "pages.dev",
    "blogspot.com", "sites.google.com", "carrd.co", "yolasite.com", "webcindario.com", "duckdns.org", "ngrok.io",
    "ngrok-free.app", "trycloudflare.com", "azurewebsites.net", "herokuapp.com", "onrender.com", "fly.dev",
}

# TLDs that dominate abuse reporting (Interisle Phishing Landscape, Spamhaus TLD
# reputation). A curated list, not a verdict: plenty of good sites use them.
ABUSED_TLDS = {
    "top", "xyz", "icu", "cyou", "sbs", "cfd", "shop", "click", "online", "site", "buzz", "rest", "bond", "vip",
    "lol", "monster", "quest", "info", "pw", "tk", "ml", "ga", "cf", "gq", "work", "support", "life", "store",
    "fun", "space", "website", "win", "bid", "loan", "cam", "mom", "ws", "zip", "mov", "live", "today", "cc",
    "su", "beauty", "hair", "skin", "makeup", "autos", "boats", "homes", "motorcycles", "yachts", "qpon", "ink",
}

SUSPICIOUS_WORDS = (
    "login", "signin", "logon", "verify", "verification", "secure", "security", "account", "update", "wallet",
    "support", "billing", "confirm", "auth", "unlock", "recover", "recovery", "password", "webscr", "invoice",
    "payment", "refund", "delivery", "parcel", "tracking", "suspend", "unusual", "validate", "kyc", "claim",
    "reward", "bonus", "airdrop", "connect", "restore", "helpdesk", "customs",
)

# Ordinary words one edit away from a brand term (looking/booking, apply/apple...).
FUZZY_STOPWORDS = {
    "looking", "cooking", "hooking", "rooking", "bookings", "booming", "telegraph", "discords", "discard", "discover",
    "amazing", "amazons", "goggle", "googly", "gaggle", "outlooks", "outlast", "metamorph", "spotfly", "zooming",
    "dropbear", "roblex", "kraked", "krakow", "netfix", "trezors", "tiktoks", "openseas", "verizons",
    "santana", "santiago", "allegra", "allegri", "allergo", "coinbased", "binances", "linkedln",
    "finance", "finances", "cloud", "clouds", "online", "posts", "postal", "postale", "correo", "import", "export",
    "report", "inport", "support", "airport", "passport", "deport", "transport", "tracker", "trader", "traders",
    "netflux",
}

# 4-letter brand terms that occur inside ordinary words, so they only count as whole tokens.
SHORT_COMMON = {"zoom", "evri", "amex", "bofa", "amzn", "usaa"}

# Unicode confusables folded to Latin (a practical subset of Unicode TR39 confusables).
CONFUSABLES = str.maketrans({
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t",
    "у": "y", "х": "x", "ѕ": "s", "і": "i", "ї": "i", "ј": "j", "ԁ": "d", "ӏ": "l", "ɡ": "g", "ԛ": "q", "ԝ": "w",
    "ь": "b", "п": "n", "г": "r", "ѵ": "v", "һ": "h", "ո": "n", "ս": "u", "օ": "o",
    # Greek
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u",
    "χ": "x", "ω": "w", "γ": "y", "μ": "u",
    # Latin lookalikes and symbols
    "ı": "i", "ł": "l", "ø": "o", "đ": "d", "ħ": "h", "ŀ": "l", "ɑ": "a", "ɩ": "i", "ʟ": "l", "ɴ": "n", "ꞵ": "b",
    "ß": "ss", "æ": "ae", "œ": "oe",
})
SWAPS = (("rn", "m"), ("vv", "w"), ("cl", "d"))
DIGIT_SWAPS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"})


@lru_cache(maxsize=1)
def brand_table() -> dict[str, dict]:
    """brand key -> {"terms": [...], "domains": set(...)} from config/brands.toml."""
    data = tomllib.loads(BRAND_FILE.read_text(encoding="utf-8")).get("brands", {})
    out = {}
    for key, b in data.items():
        terms = [re.sub(r"[^a-z0-9]", "", t.lower()) for t in b.get("terms", [])]
        out[key] = {"terms": [t for t in terms if t], "domains": {d.lower() for d in b.get("domains", [])}}
    return out


@lru_cache(maxsize=1)
def _terms_by_brand() -> list[tuple[str, str]]:
    return [(brand, t) for brand, b in brand_table().items() for t in b["terms"]]


# ------------------------------------------------------------------ string helpers

def decode_label(label: str) -> str:
    """Punycode label -> Unicode (IDNA). Undecodable labels are returned unchanged."""
    if not label.startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        try:
            return label[4:].encode("ascii").decode("punycode")
        except (UnicodeError, ValueError):
            return label


def skeleton(text: str) -> str:
    """Latin skeleton: confusables folded, accents stripped, lower case."""
    text = text.lower().translate(CONFUSABLES)
    text = unicodedata.normalize("NFKD", text)
    return "".join(c for c in text if not unicodedata.combining(c))


def fold_swaps(text: str) -> str:
    text = text.translate(DIGIT_SWAPS)
    for a, b in SWAPS:
        text = text.replace(a, b)
    return text


def osa_distance(a: str, b: str, limit: int) -> int:
    """Optimal string alignment distance (Damerau-Levenshtein with adjacent swaps), early exit past limit."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def _tokens(text: str) -> list[str]:
    """Label parts split on non-alphanumerics, plus the joined form (last) for exact matching."""
    parts = [t for t in re.split(r"[^a-z0-9]+", text) if t]
    joined = "".join(parts)
    return parts + ([joined] if len(parts) > 1 else [])


def _fuzzy_ok(cand: str, term: str) -> int | None:
    """Edit distance of a lookalike candidate, or None. Rules chosen to keep false positives down:
    the first letter must match (typosquats keep it; swaps like 0/o are handled by folding),
    6-letter terms allow one substitution or swap only, 7-8 letters one edit, 9+ letters two."""
    if cand == term or cand in FUZZY_STOPWORDS or not cand or cand[0] != term[0]:
        return None
    if len(term) == 6:
        # one substitution or swap; an insertion only if first and last letters both hold ("robliox")
        if not (len(cand) == 6 or (len(cand) == 7 and cand[-1] == term[-1])):
            return None
        lim = 1
    else:
        lim = 2 if len(term) >= 9 else 1
    d = osa_distance(cand, term, lim)
    return d if 0 < d <= lim else None


def _match_token(tok: str, term: str, fuzzy: bool = True) -> tuple[str, int] | None:
    """How a single token relates to a brand term: ('token'|'label'|'lookalike', distance)."""
    if tok == term:
        return "token", 0
    if len(term) >= 6 and term in tok:
        return "label", 0
    if len(term) == 5 and len(tok) > len(term) and tok.startswith(term):
        return "label", 0
    if len(term) == 4 and term not in SHORT_COMMON and term in tok:
        return "label", 0       # distinctive 4-letter brands (hsbc, usps, bbva) inside a label
    if not fuzzy or len(term) < 6 or tok in FUZZY_STOPWORDS:
        return None
    d = _fuzzy_ok(tok, term)
    if d:
        return "lookalike", d
    # lookalike glued to the start or end of a longer token ("trezurslogons", "securepaypai")
    if len(tok) > len(term) and not any(w in tok for w in FUZZY_STOPWORDS):
        sizes = (len(term),) if len(term) == 6 else (len(term), len(term) + 1)
        for size in sizes:
            for w in (tok[:size], tok[-size:]):
                d = _fuzzy_ok(w, term)
                if d == 1:       # windows: one edit only
                    return "lookalike", d
    return None


# ------------------------------------------------------------------ analysis

KIND_POINTS = {"homoglyph": P["homoglyph"], "lookalike": P["lookalike"], "token": P["brand-token"],
               "label": P["brand-in-label"], "path": P["brand-in-path"]}


def brand_evidence(host_labels: list[str], path: str, reg: str) -> dict[str, dict]:
    """brand -> best evidence {kind, term, seen, distance, points}.

    Each host label is checked as written (punycode decoded) and again after
    homoglyph skeleton + character-swap folding. A brand that is plainly visible
    counts as token/label evidence; one that only appears after folding counts
    as a homoglyph lookalike, the strongest signal.
    """
    plain, folded = [], []
    for raw in host_labels:
        uni = decode_label(raw).lower()
        plain.append((raw, _tokens(uni)))
        skel = skeleton(uni)
        for text in {skel, fold_swaps(skel)} - {uni}:
            folded.append((raw, _tokens(text)))
    best: dict[str, dict] = {}

    def offer(brand, ev):
        if brand not in best or ev["points"] > best[brand]["points"]:
            best[brand] = ev

    def first_match(variants, term):
        for raw, toks in variants:
            for i, tok in enumerate(toks):
                joined = len(toks) > 1 and i == len(toks) - 1   # cross-hyphen form: exact matches only
                m = _match_token(tok, term, fuzzy=not joined)
                if m:
                    return raw, tok, m
        return None

    table = brand_table()
    for brand, term in _terms_by_brand():
        if reg in table[brand]["domains"]:
            continue
        p = first_match(plain, term)
        if p and p[2][0] in ("token", "label"):
            offer(brand, {"kind": p[2][0], "term": term, "seen": p[1], "distance": 0, "points": KIND_POINTS[p[2][0]]})
            continue
        f = first_match(folded, term)
        if f and f[2][0] in ("token", "label"):
            offer(brand, {"kind": "homoglyph", "term": term, "seen": f[0], "distance": 0, "points": KIND_POINTS["homoglyph"]})
            continue
        hit = p or f
        if hit:
            offer(brand, {"kind": "lookalike", "term": term, "seen": hit[1], "distance": hit[2][1],
                          "points": KIND_POINTS["lookalike"]})
            continue
        if brand not in best and len(term) >= 4 and path:
            ptoks = _tokens(path)
            if term in ptoks or (len(term) >= 6 and any(term in t for t in ptoks)):
                offer(brand, {"kind": "path", "term": term, "seen": term, "distance": 0, "points": KIND_POINTS["path"]})
    return best


def analyse(url: str, *, registered: str | None = None, feeds: int = 1, now: float | None = None) -> dict:
    """Break a (possibly defanged) URL or domain into the parts used for phishing stats and score it.

    registered  RDAP registration date of the registered domain, if it was looked up
    feeds       number of phishing feeds that list this URL/domain
    """
    real = defang.canonical_url(url)
    host = defang.url_host(real)
    is_ip = psl.is_ip(host)
    sub, label, suffix = psl.split(host) if not is_ip else ("", host, "")
    reg = psl.registered_domain(host)
    try:
        parts = urlsplit(real)
        userinfo = parts.netloc.rsplit("@", 1)[0] + "@" if "@" in parts.netloc else ""
        path = (userinfo + parts.path + ("?" + parts.query if parts.query else "")).lower()
    except ValueError:
        path = ""
    if path == "/":
        path = ""
    host_labels = [] if is_ip else [x for x in (sub.split(".") if sub else []) + [label] if x]
    tld = "" if is_ip else psl.tld(host)
    idn = any(x.startswith("xn--") for x in host.split("."))
    unicode_host = ".".join(decode_label(x) for x in host.split(".")) if idn else host

    hosting = None
    if suffix and psl.is_private_suffix(suffix):
        hosting = suffix
    elif reg in HOSTING_DOMAINS:
        hosting = reg

    evidence = brand_evidence(host_labels, path, reg) if host else {}
    ranked = sorted(evidence.items(), key=lambda kv: -kv[1]["points"])
    reasons, score = [], 0

    def add(points, why):
        nonlocal score
        score += points
        reasons.append(f"+{points} {why}")

    if ranked:
        b, ev = ranked[0]
        desc = {"homoglyph": f"homoglyph/character-swap lookalike of {b} (label '{ev['seen']}' folds to '{ev['term']}')",
                "lookalike": f"lookalike of {b}: '{ev['seen']}' is {ev['distance']} edit(s) from '{ev['term']}'",
                "token": f"brand '{ev['term']}' ({b}) as a host token",
                "label": f"brand '{ev['term']}' ({b}) inside host label '{ev['seen']}'",
                "path": f"brand '{ev['term']}' ({b}) only in the URL path"}[ev["kind"]]
        add(ev["points"], desc)
    if idn:
        add(P["punycode"], f"punycode host (displays as {unicode_host})")
    words = sorted({w for w in SUSPICIOUS_WORDS if w in (sub + "." + label + path)})
    if words:
        add(min(P["keyword_max"], P["keyword"] * len(words)), "suspicious words: " + ", ".join(words[:6]))
    if tld in ABUSED_TLDS:
        add(P["tld"], f"high-abuse TLD .{tld}")
    if hosting:
        add(P["hosting"], f"free hosting / site builder ({hosting})")
    if is_ip:
        add(P["ip-host"], "raw IP address as host")
    depth = 0 if not sub else sub.count(".") + 1
    if depth >= 3:
        add(P["deep-subdomain"], f"{depth} subdomain levels")
    if len(host) > 40:
        add(P["long-host"], f"long host ({len(host)} chars)")
    shown_label = decode_label(label)
    if shown_label.count("-") >= 2:
        add(P["hyphens"], f"{shown_label.count('-')} hyphens in '{shown_label}'")
    if registered:
        age = timeutil.days_ago(timeutil.parse(registered), now)
        if age < 30:
            add(P["new-30d"], f"registered {age:.0f} days ago (RDAP)")
        elif age < 180:
            add(P["new-180d"], f"registered {age:.0f} days ago (RDAP)")
    if feeds >= 2:
        add(P["multi-feed"], f"listed by {feeds} phishing feeds")

    return {
        "host": host, "reg_domain": reg, "tld": tld, "suffix": suffix,
        "is_ip_host": is_ip, "brands": [b for b, _ in ranked], "hosting": hosting,
        "subdomain_depth": depth,
        "score": min(100, score), "reasons": reasons, "method": ranked[0][1]["kind"] if ranked else None,
        "evidence": {b: ev for b, ev in ranked}, "idn": idn, "unicode_host": unicode_host,
    }
