"""Offline demo: load the bundled fixtures through the normal collectors, then correlate.

`python -m threatintel seed` needs no network. Each collector reads its file from
fixtures/ instead of the internet but uses the same normalise/store code, so the
fixture path exercises the real parsers. Runs are logged with mode='fixture'.
"""
from __future__ import annotations

import json
import time

from . import collectors, config, correlate, db
from .config import FIXTURES


def manifest() -> dict:
    p = FIXTURES / "MANIFEST.json"
    return json.loads(p.read_text()) if p.exists() else {}


def load_rdap_fixture(conn) -> str:
    """Pre-fill the RDAP cache with real lookups saved from a live run, so the offline demo shows
    registration data and the new-registration signal. Rows keep their original fetch time."""
    p = FIXTURES / "rdap-cache.json"
    if not p.exists():
        return "no fixture"
    rows = json.loads(p.read_text())
    for r in rows:
        r = {**r, "statuses": json.dumps(r.get("statuses") or [])}
        conn.execute("""INSERT OR REPLACE INTO rdap(key, kind, query, status, registered, expires, last_changed, registrar,
                        abuse_email, abuse_phone, network, country, statuses, server, error, fetched_at)
                        VALUES (:key,:kind,:query,:status,:registered,:expires,:last_changed,:registrar,:abuse_email,
                        :abuse_phone,:network,:country,:statuses,:server,:error,:fetched_at)""",
                     {k: r.get(k) for k in ("key", "kind", "query", "status", "registered", "expires", "last_changed",
                                            "registrar", "abuse_email", "abuse_phone", "network", "country",
                                            "statuses", "server", "error", "fetched_at")})
    conn.commit()
    return f"seeded rows={len(rows)}"


def run(fresh: bool = False, conn=None) -> dict:
    t0 = time.time()
    if fresh and conn is None:
        path = config.get().db_path
        for suffix in ("", "-wal", "-shm"):
            p = path.with_name(path.name + suffix)
            if p.exists():
                p.unlink()
    own = conn is None
    conn = conn or db.connect()
    results = {}
    try:
        for name, cls in collectors.REGISTRY.items():
            if not all((FIXTURES / f).exists() for f in cls.fixture_files):
                results[name] = "no fixture"
                continue
            r = collectors.run_feed(name, mode="fixture", conn=conn)
            results[name] = f"{r['status']} rows={r['rows']}" + (f" ({r['error'][:120]})" if r.get("error") else "")
        results["rdap"] = load_rdap_fixture(conn)
        stats = correlate.run(conn)
        db.set_meta(conn, "seeded_at", time.time())
        conn.commit()
    finally:
        if own:
            conn.close()
    return {"feeds": results, "correlate": stats, "seconds": round(time.time() - t0, 2)}
