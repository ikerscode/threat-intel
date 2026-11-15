"""Collector base class.

Every collector follows the same three steps:

    raw     = fetch()            live network (through fetch.get) ...
    raw     = load_fixture(dir)  ... or the bundled snapshot in fixtures/
    records = normalise(raw)     pure function, easy to test
    n       = store(conn, recs)  writes to SQLite, returns rows written

`run_feed()` in collectors/__init__.py wraps this with feed_runs logging.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .. import config, fetch, secrets


class SkipFeed(Exception):
    """Raised when a feed cannot run (for example a missing optional API key)."""


class Collector:
    name: str = ""
    title: str = ""
    homepage: str = ""
    licence: str = ""
    fixture_files: tuple[str, ...] = ()
    requires_env: str | None = None        # env var that must be set to run live
    optional_env: str | None = None        # env var that is used when present
    context_only: bool = False             # True for feeds that tag, not accuse (Tor)

    # ------------------------------------------------------------ helpers
    @property
    def cfg(self) -> dict:
        return config.get().feed(self.name)

    def get(self, url: str, **kw) -> fetch.FetchResult:
        cfg = self.cfg
        kw.setdefault("min_refetch_s", cfg.get("min_refetch_s", 0))
        kw.setdefault("timeout_s", cfg.get("timeout_s", 30))
        if "host_interval_s" in cfg:
            kw.setdefault("host_interval_s", cfg["host_interval_s"])
        res = fetch.get(url, feed=self.name, **kw)
        self.notes.append(res.note or f"HTTP {res.status}")
        return res

    def env(self, var: str | None) -> str | None:
        return secrets.get(var) if var else None

    # ------------------------------------------------------------ steps
    def check_live(self) -> None:
        if self.requires_env and not self.env(self.requires_env):
            raise SkipFeed(f"{self.requires_env} not set; this source needs a free API key")

    def fetch(self):
        raise NotImplementedError

    def load_fixture(self, fixture_dir: Path):
        """Default: one JSON fixture file."""
        path = fixture_dir / self.fixture_files[0]
        if path.suffix == ".json":
            return json.loads(path.read_text(encoding="utf-8"))
        return path.read_text(encoding="utf-8")

    def normalise(self, raw) -> list[dict]:
        raise NotImplementedError

    def store(self, conn, records: list[dict]) -> int:
        raise NotImplementedError

    def __init__(self) -> None:
        self.notes: list[str] = []


def stable_sample(values: list[str], limit: int) -> list[str]:
    """Keep at most `limit` values, chosen by hash rather than by position.

    Big lists are sorted by IP or listed in no useful order, so "the first N"
    would always keep the same address ranges. Bottom-k by SHA-1 gives a fair
    sample that is also stable from one day to the next: a value that stays on
    the list stays in the sample, which keeps first/last-seen history meaningful.
    """
    uniq = list(dict.fromkeys(values))
    if limit <= 0 or len(uniq) <= limit:
        return uniq
    return sorted(uniq, key=lambda v: hashlib.sha1(v.encode()).digest())[:limit]


def comment_lines(text: str, prefixes: tuple[str, ...] = ("#", ";")) -> list[str]:
    """Non-empty, non-comment lines with inline comments removed."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(prefixes):
            continue
        out.append(line.split("#", 1)[0].split(";", 1)[0].strip())
    return [x for x in out if x]
