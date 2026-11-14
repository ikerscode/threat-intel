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
}
HALF_LIFE_DAYS = {"ip": 30, "url": 14, "domain": 45, "cidr": 180, "hash": 365}
RECENCY_FLOOR = 0.25

INDICATOR_FORMULA = ("confidence = round(100 * C * (0.25 + 0.75 * R)),  C = 1 - prod(1 - w_source),  "
                     "R = 0.5^(age_days / half_life)")
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
