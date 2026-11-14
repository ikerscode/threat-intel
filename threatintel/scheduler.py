"""Background scheduler: runs each enabled feed when its interval has elapsed.

One daemon thread wakes every `tick_s` seconds, looks at the last successful
live run of each feed and starts the ones that are due, one at a time (so we
never hammer several hosts at once). After any successful run it re-correlates.
It can be switched on/off at runtime from the HUD; the default comes from
config/feeds.toml [scheduler].
"""
from __future__ import annotations

import logging
import threading
import time

from . import collectors, config, correlate, db

log = logging.getLogger("threatintel.scheduler")


class Scheduler:
    def __init__(self):
        cfg = config.get().scheduler
        self.enabled = bool(cfg.get("enabled", False))
        self.tick_s = float(cfg.get("tick_s", 60))
        self.correlate_after = bool(cfg.get("correlate_after", True))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_tick: float | None = None
        self.current: str | None = None
        self.history: list[dict] = []

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="ti-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def set_enabled(self, enabled: bool) -> None:
        self.enabled = enabled

    def due_feeds(self, conn) -> list[str]:
        due = []
        now = time.time()
        for name in collectors.REGISTRY:
            if not collectors.is_enabled(conn, name):
                continue
            interval = float(config.get().feed(name).get("interval_min", 1440)) * 60
            last = conn.execute("""SELECT MAX(started) FROM feed_runs WHERE feed=? AND mode='live'
                                   AND status IN ('ok','cached','skipped','error','stale')""", (name,)).fetchone()[0]
            if last is None or now - last >= interval:
                due.append(name)
        return due

    def tick(self) -> list[dict]:
        """Run every due feed once. Public so tests and the CLI can drive it."""
        self.last_tick = time.time()
        ran = []
        with db.session() as conn:
            for name in self.due_feeds(conn):
                if self._stop.is_set() or not self.enabled:
                    break
                self.current = name
                r = collectors.run_feed(name, conn=conn)
                ran.append({"feed": name, "status": r.get("status"), "rows": r.get("rows")})
            self.current = None
            if self.correlate_after and any(r["status"] in ("ok", "stale") for r in ran):
                correlate.run(conn)
        self.history = (ran + self.history)[:50]
        return ran

    def _loop(self) -> None:
        while not self._stop.wait(self.tick_s if self.last_tick else 5):
            if not self.enabled:
                self.last_tick = time.time()
                continue
            try:
                self.tick()
            except Exception:  # never let one bad tick kill the thread
                log.exception("scheduler tick failed")

    def status(self) -> dict:
        return {"enabled": self.enabled, "running": bool(self._thread and self._thread.is_alive()),
                "tick_s": self.tick_s, "last_tick": self.last_tick, "current": self.current,
                "recent": self.history[:10]}
