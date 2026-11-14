"""Scoring formulas behave as documented."""
import time

from threatintel import scoring


def test_corroboration_noisy_or():
    assert scoring.corroboration([]) == 0
    assert abs(scoring.corroboration([0.5, 0.5]) - 0.75) < 1e-9
    assert scoring.corroboration([0.0]) == 0  # Tor alone carries no weight


def test_indicator_confidence_decays():
    now = time.time()
    fresh, _ = scoring.indicator_confidence("ip", [0.85], now, now)
    month, _ = scoring.indicator_confidence("ip", [0.85], now - 30 * 86400, now)
    multi, parts = scoring.indicator_confidence("ip", [0.85, 0.75], now, now)
    assert fresh == 85
    assert month == round(100 * 0.85 * (0.25 + 0.75 * 0.5))
    assert multi > fresh and parts["sources"] == 2


def test_vuln_priority_formula():
    total, parts = scoring.vuln_priority(in_kev=True, epss=0.5, cvss=9.8, ransomware=True,
                                         date_added="2026-01-01", now=time.mktime((2026, 1, 1, 0, 0, 0, 0, 0, 0)))
    assert parts["kev"] == 20 and parts["epss"] == 15 and parts["ransomware"] == 15
    assert abs(parts["cvss"] - 24.5) < 1e-9
    assert 9.9 <= parts["recency"] <= 10
    assert abs(total - (20 + 15 + 24.5 + 15 + parts["recency"])) < 0.11
    low, p2 = scoring.vuln_priority(in_kev=True, epss=None, cvss=None, ransomware=False, date_added=None)
    assert p2["cvss_assumed"] and low < total
