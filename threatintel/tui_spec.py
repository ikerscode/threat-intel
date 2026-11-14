"""Terminal HUD spec for threat-intel: views and actions over the local API (see termhud.py).

Mirrors the web HUD: overview counts, the prioritised vulnerability list, ransomware
groups and feed status. Enter on a row pivots into search for that CVE, group or feed
history. Slow or networked actions ask for confirmation first.
"""
from __future__ import annotations

SPEC = {
    "title": "THREAT-INTEL",
    "views": [
        {"name": "Overview", "endpoint": "/api/overview", "path": "counts"},
        {"name": "Vulns", "endpoint": "/api/vulns?limit=60",
         "rows": "rows",
         "columns": [["cve", 16], ["vendor", 14], ["product", 18], ["priority", 9],
                     ["ransomware_use", 12], ["date_added", 12]],
         "detail": "/api/search?q={cve}"},
        {"name": "Ransomware", "endpoint": "/api/ransomware?days=30",
         "rows": "groups",
         "columns": [["name", 22], ["attack_id", 10], ["d7", 6], ["d30", 6], ["top_sectors", 30]],
         "detail": "/api/search?q={name}"},
        {"name": "Feeds", "endpoint": "/api/feeds",
         "rows": "feeds",
         "columns": [["feed", 12], ["enabled", 8], ["last_run.status", 10], ["last_run.rows", 8],
                     ["interval_min", 12], ["key_env", 20]],
         "detail": "/api/feeds/runs?feed={feed}&limit=25"},
    ],
    "actions": [
        {"key": "c", "label": "correlate", "method": "POST", "endpoint": "/api/correlate",
         "confirm": True},
        {"key": "b", "label": "brief", "method": "POST", "endpoint": "/api/reports?days=7",
         "confirm": True},
        {"key": "f", "label": "refresh feed (Feeds view)", "method": "POST",
         "endpoint": "/api/feeds/{feed}/refresh", "confirm": True},
        {"key": "s", "label": "load demo data", "method": "POST", "endpoint": "/api/seed",
         "confirm": True},
    ],
    "refresh": 10,
}
