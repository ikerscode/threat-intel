"""Date parsing helpers. Feeds use several formats; everything becomes epoch seconds (UTC)."""
from __future__ import annotations

import time
from datetime import datetime, timezone

FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S")


def parse(value) -> float | None:
    if value in (None, "", "None"):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        pass
    for fmt in FORMATS:
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def iso_date(epoch: float | None) -> str:
    if not epoch:
        return ""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")


def iso(epoch: float | None) -> str:
    if not epoch:
        return ""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def days_ago(epoch: float | None, ref: float | None = None) -> float:
    if not epoch:
        return 9999.0
    return max(0.0, ((ref or time.time()) - epoch) / 86400)
