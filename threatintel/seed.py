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
        stats = correlate.run(conn)
        db.set_meta(conn, "seeded_at", time.time())
        conn.commit()
    finally:
        if own:
            conn.close()
    return {"feeds": results, "correlate": stats, "seconds": round(time.time() - t0, 2)}
