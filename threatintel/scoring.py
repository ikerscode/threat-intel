"""Scoring formulas. Kept in one place so the HUD, README and brief show the same maths.

Indicator confidence (0-100)
    w_s      per-source weight (SOURCE_WEIGHTS; ThreatFox uses its own confidence_level/100)
    C        = 1 - prod(1 - w_s)                       noisy-OR corroboration over sources
    R        = 0.5 ** (age_days / half_life[type])     recency decay since last_seen
    score    = round(100 * C * (0.25 + 0.75 * R))
    An IP inside a Spamhaus DROP netblock gets an extra pseudo-source with w = 0.4.
    Tor exit sightings have w = 0: Tor is context, not evidence of maliciousness.

Vulnerability priority (0-100)
    priority = 20*KEV + 30*EPSS + 25*(CVSS/10) + 15*RANSOMWARE + 10*0.5**(days_since_KEV_add / 180)
    KEV and RANSOMWARE are 0/1, EPSS is the 30-day exploitation probability (0-1),
    CVSS is the NVD base score (7.0 assumed and flagged when NVD has not been collected).

Phishing impersonation score (0-100), see phishing.py and PHISH_POINTS
    brand evidence (largest one only): homoglyph/IDN or character-swap lookalike 40,
      edit-distance lookalike 35, brand token in host 30, brand inside a host label 25,
      brand only in the path 15
    + punycode host 10, suspicious keywords 5 each (max 20), high-abuse TLD 10,
      free hosting / site builder 10, IP address host 15, 3+ subdomain levels 5,
      host over 40 characters 5, 2+ hyphens in the registered label 5,
      registered < 30 days ago 20 or < 180 days 10 (RDAP, when looked up),
      listed by 2+ phishing feeds 10
    capped at 100. Every point added is listed as a reason.
"""
from __future__ import annotations

import math
import time

from . import timeutil

SOURCE_WEIGHTS = {
    "feodo": 0.85,
    "spamhaus": 0.90,
    "threatfox": 0.75,
    "urlhaus": 0.75,
    "openphish": 0.70,
    "tor": 0.0,
    "drop-containment": 0.40,
    "enrich": 0.15,
    # added 2026-11-14
    "sslbl": 0.85,            # C2 certificate seen by abuse.ch on a live C2
    "circl": 0.60,            # to_ids attributes in published OSINT reports (often older campaigns)
    "phishing_army": 0.60,    # aggregated phishing domains, filtered for false positives
    "otx": 0.55,              # community pulses, quality varies
    "et_compromised": 0.55,   # hosts seen compromised / attacking, no context given
    "blocklistde": 0.50,      # fail2ban reports of brute force
    "cins": 0.45,             # reputation score list, broad
}
HALF_LIFE_DAYS = {"ip": 30, "url": 14, "domain": 45, "cidr": 180, "hash": 365}
RECENCY_FLOOR = 0.25

INDICATOR_FORMULA = ("confidence = round(100 * C * (0.25 + 0.75 * R)),  C = 1 - prod(1 - w_source),  "
                     "R = 0.5^(age_days / half_life)")
PHISH_POINTS = {
    "homoglyph": 40, "lookalike": 35, "brand-token": 30, "brand-in-label": 25, "brand-in-path": 15,
    "punycode": 10, "keyword": 5, "keyword_max": 20, "tld": 10, "hosting": 10, "ip-host": 15,
    "deep-subdomain": 5, "long-host": 5, "hyphens": 5, "new-30d": 20, "new-180d": 10, "multi-feed": 10,
}
PHISH_FORMULA = ("phish score = max(brand evidence: homoglyph 40 | lookalike 35 | brand token 30 | in label 25 | "
                 "in path 15) + punycode 10 + keywords 5 each (max 20) + abused TLD 10 + free hosting 10 + IP host 15 "
                 "+ deep subdomain 5 + long host 5 + hyphens 5 + registered <30d 20 / <180d 10 + 2+ feeds 10, cap 100")
VULN_FORMULA = ("priority = 20*KEV + 30*EPSS + 25*(CVSS/10) + 15*RANSOMWARE + 10*0.5^(days_since_KEV_add/180)")


def corroboration(weights: list[float]) -> float:
    p = 1.0
    for w in weights:
        p *= 1.0 - max(0.0, min(1.0, w))
    return 1.0 - p


def recency(last_seen: float | None, itype: str, now: float | None = None) -> float:
    age = timeutil.days_ago(last_seen, now)
    return 0.5 ** (age / HALF_LIFE_DAYS.get(itype, 30))


def indicator_confidence(itype: str, source_weights: list[float], last_seen: float | None,
                         now: float | None = None) -> tuple[int, dict]:
    c = corroboration(source_weights)
    r = recency(last_seen, itype, now)
    score = round(100 * c * (RECENCY_FLOOR + (1 - RECENCY_FLOOR) * r))
    return score, {"C": round(c, 3), "R": round(r, 3), "sources": len([w for w in source_weights if w > 0])}


def vuln_priority(*, in_kev: bool, epss: float | None, cvss: float | None, ransomware: bool,
                  date_added: str | None, now: float | None = None) -> tuple[float, dict]:
    now = now or time.time()
    added = timeutil.parse(date_added)
    days = timeutil.days_ago(added, now) if added else 3650
    cvss_assumed = cvss is None
    parts = {
        "kev": 20.0 if in_kev else 0.0,
        "epss": round(30.0 * (epss or 0.0), 2),
        "cvss": round(25.0 * ((7.0 if cvss_assumed else cvss) / 10.0), 2),
        "ransomware": 15.0 if ransomware else 0.0,
        "recency": round(10.0 * math.pow(0.5, days / 180.0), 2),
    }
    total = round(sum(parts.values()), 1)
    parts["cvss_assumed"] = cvss_assumed
    return total, parts
