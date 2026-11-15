"""Collector registry and the run wrapper that logs every run to feed_runs."""
from __future__ import annotations

import logging
import os
import threading
import traceback
from pathlib import Path

from .. import config, db, secrets
from ..config import FIXTURES
from ..fetch import FetchError
from .attack import AttackCollector
from .base import Collector, SkipFeed
from .circl import CirclOsintCollector
from .epss import EpssCollector
from .feodo import FeodoCollector
from .ip2asn import Ip2asnCollector
from .iplists import BlocklistDeCollector, CinsCollector, EtCompromisedCollector
from .kev import KevCollector
from .nvd import NvdCollector
from .openphish import OpenphishCollector
from .otx import OtxCollector
from .phishingarmy import PhishingArmyCollector
from .ransomware import RansomwareCollector
from .spamhaus import SpamhausCollector
from .sslbl import SslblCollector
from .threatfox import ThreatfoxCollector
from .tor import TorCollector
from .urlhaus import UrlhausCollector

log = logging.getLogger("threatintel.collect")

# Order matters: KEV before EPSS/NVD (they enrich KEV CVEs).
REGISTRY: dict[str, type[Collector]] = {c.name: c for c in (
    KevCollector, EpssCollector, NvdCollector, AttackCollector, FeodoCollector, UrlhausCollector,
    ThreatfoxCollector, OpenphishCollector, RansomwareCollector, SpamhausCollector, TorCollector, Ip2asnCollector,
    SslblCollector, EtCompromisedCollector, CinsCollector, BlocklistDeCollector, PhishingArmyCollector,
    CirclOsintCollector, OtxCollector,
)}

_run_locks = {name: threading.Lock() for name in REGISTRY}


def get(name: str) -> Collector:
    if name not in REGISTRY:
        raise KeyError(f"unknown feed {name!r}; known: {', '.join(REGISTRY)}")
    return REGISTRY[name]()


def is_enabled(conn, name: str) -> bool:
    row = conn.execute("SELECT enabled_override FROM feed_state WHERE feed=?", (name,)).fetchone()
    if row and row["enabled_override"] is not None:
        return bool(row["enabled_override"])
    return bool(config.get().feed(name).get("enabled", False))


def set_enabled(conn, name: str, enabled: bool | None) -> None:
    get(name)
    conn.execute("INSERT INTO feed_state(feed, enabled_override) VALUES (?, ?) "
                 "ON CONFLICT(feed) DO UPDATE SET enabled_override=excluded.enabled_override",
                 (name, None if enabled is None else int(enabled)))
    conn.commit()


def run_feed(name: str, *, mode: str = "live", conn=None, fixture_dir: Path | None = None) -> dict:
    """Run one collector end to end and record the outcome in feed_runs.

    mode="live" uses the network (through the polite fetcher); mode="fixture"
    loads the bundled snapshot instead. Returns the feed_runs row as a dict.
    """
    collector = get(name)
    own = conn is None
    conn = conn or db.connect()
    lock = _run_locks[name]
    if not lock.acquire(blocking=False):
        return {"feed": name, "status": "busy", "error": "a run for this feed is already in progress"}
    run_id = db.start_run(conn, name, mode)
    status, rows_, error = "ok", 0, None
    try:
        if mode == "fixture":
            raw = collector.load_fixture(fixture_dir or FIXTURES)
        else:
            collector.check_live()
            raw = collector.fetch(conn)
        records = collector.normalise(raw)
        rows_ = collector.store(conn, records)
        keep_days = collector.cfg.get("retention_days")
        if keep_days and mode == "live":
            # rotating bulk lists: forget entries that have not been on the list for keep_days
            pruned = db.prune_source(conn, name, float(keep_days))
            if pruned:
                log.info("feed %s: pruned %d indicators older than %s days", name, pruned, keep_days)
        conn.commit()
        if mode == "fixture":
            status = "seeded"
        elif collector.notes and all(n in ("fresh cache", "304 not modified") for n in collector.notes):
            status = "cached"
        elif any(n.startswith("network error") for n in collector.notes):
            status, error = "stale", "; ".join(n for n in collector.notes if n.startswith("network error"))
    except SkipFeed as exc:
        conn.rollback()
        status, error = "skipped", str(exc)
    except (FetchError, OSError, ValueError, KeyError) as exc:
        conn.rollback()
        status, error = "error", f"{type(exc).__name__}: {exc}"
        log.warning("feed %s failed: %s", name, error)
    except Exception as exc:  # keep the scheduler alive whatever a parser does
        conn.rollback()
        status, error = "error", f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=3)}"
        log.exception("feed %s crashed", name)
    finally:
        db.finish_run(conn, run_id, status, rows_, error)
        lock.release()
    result = db.one(conn, "SELECT * FROM feed_runs WHERE id=?", (run_id,))
    if own:
        conn.close()
    return result


def feed_status(conn) -> list[dict]:
    """One row per feed for the HUD: config, override, last run, last success."""
    out = []
    for name, cls in REGISTRY.items():
        cfg = config.get().feed(name)
        last = db.one(conn, "SELECT * FROM feed_runs WHERE feed=? ORDER BY id DESC LIMIT 1", (name,))
        last_ok = db.one(conn, "SELECT * FROM feed_runs WHERE feed=? AND status IN ('ok','cached','seeded','stale') "
                               "ORDER BY id DESC LIMIT 1", (name,))
        override = conn.execute("SELECT enabled_override FROM feed_state WHERE feed=?", (name,)).fetchone()
        key_env = cls.requires_env or cls.optional_env
        out.append({
            "feed": name, "title": cls.title, "homepage": cls.homepage, "licence": cls.licence,
            "enabled": is_enabled(conn, name), "config_enabled": bool(cfg.get("enabled", False)),
            "override": None if not override else override["enabled_override"],
            "interval_min": cfg.get("interval_min"),
            "key_env": key_env, "key_required": bool(cls.requires_env),
            "key_present": bool(key_env and secrets.get(key_env)),
            "context_only": cls.context_only,
            "last_run": last, "last_ok": last_ok,
        })
    return out
