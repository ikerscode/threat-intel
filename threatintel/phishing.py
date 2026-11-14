"""Offline analysis of phishing URLs: brand impersonation, TLDs and hosting.

Nothing here touches the network. A URL is split into host, registered domain
(via psl.py) and path, then matched against a small keyword table. A brand is
only reported when its keyword appears and the registered domain is not one of
the brand's own domains (paypal.com itself is not impersonating PayPal).
"""
from __future__ import annotations

import re

from . import defang, psl

# brand -> (keywords, legitimate registered domains)
BRANDS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
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

# Registered domains that belong to free hosting / site builders (not in the PSL private section).
HOSTING_DOMAINS = {
    "weebly.com", "wordpress.com", "000webhostapp.com", "godaddysites.com", "jimdosite.com", "mystrikingly.com",
    "google.com", "googleapis.com", "ipfs.io", "dweb.link", "glitch.me", "webnode.page", "teachable.com",
    "canva.site", "gamma.site", "start.page", "wcomhost.com", "sharepoint.com", "office.com", "zohopublic.com",
    "typeform.com", "jotform.com", "forms.gle", "plesk.page", "ukit.me", "tilda.ws", "ucraft.site",
}


def analyse(url: str) -> dict:
    """Break a (possibly defanged) URL into the parts used for phishing stats."""
    real = defang.canonical_url(url)
    host = defang.url_host(real)
    is_ip = psl.is_ip(host)
    sub, label, suffix = psl.split(host) if not is_ip else ("", host, "")
    reg = psl.registered_domain(host)
    haystack = re.sub(r"[^a-z0-9.\-/]", "", real.lower().split("://", 1)[-1])
    brands = []
    for brand, (keywords, legit) in BRANDS.items():
        if reg in legit:
            continue
        if any(k in haystack for k in keywords):
            brands.append(brand)
    hosting = None
    if suffix and psl.is_private_suffix(suffix):
        hosting = suffix
    elif reg in HOSTING_DOMAINS:
        hosting = reg
    return {
        "host": host, "reg_domain": reg, "tld": "" if is_ip else psl.tld(host), "suffix": suffix,
        "is_ip_host": is_ip, "brands": brands, "hosting": hosting,
        "subdomain_depth": 0 if not sub else sub.count(".") + 1,
    }
