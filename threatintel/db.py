"""SQLite storage: schema and small helpers shared by collectors and the engine.

Design notes
- `indicators` holds one row per (type, value). Every feed that reports the
  indicator adds a row to `sightings`, which is what corroboration scoring uses.
- URL and domain values are stored defanged (hxxp://, [.]) so nothing in the
  database or the HUD is a clickable live link.
- `actor_records` keeps each source's view of a group (ATT&CK group, ransomware.live
  group). The correlation step merges them into `actors` + `actor_aliases`.
- `relationships` is a generic edge table. Node ids are typed strings such as
  "technique:T1059", "actor:lockbit", "malware:qakbot", "ip:1.2.3.4".
  Edges written by the correlation engine use source = 'correlate' and are
  rebuilt on every run.
"""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY,
    type TEXT NOT NULL,              -- ip | cidr | domain | url | hash
    value TEXT NOT NULL,             -- defanged for url/domain
    first_seen REAL,
    last_seen REAL,
    sources TEXT DEFAULT '[]',       -- JSON list of feed names
    tags TEXT DEFAULT '[]',          -- JSON list
    confidence REAL DEFAULT 0,       -- 0..100, set by correlation
    malware TEXT,                    -- normalised family key if known
    asn INTEGER,
    as_name TEXT,
    country TEXT,
    host TEXT,                       -- url only: defanged host
    reg_domain TEXT,                 -- url/domain: defanged registered domain
    context_only INTEGER DEFAULT 0,  -- 1 when only context feeds (e.g. Tor) report it
    UNIQUE(type, value)
);
CREATE INDEX IF NOT EXISTS ix_ind_malware ON indicators(malware);
CREATE INDEX IF NOT EXISTS ix_ind_regdom ON indicators(reg_domain);

CREATE TABLE IF NOT EXISTS sightings (
    indicator_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    first_seen REAL,
    last_seen REAL,
    malware TEXT,
    tags TEXT DEFAULT '[]',
    extra TEXT DEFAULT '{}',
    PRIMARY KEY (indicator_id, source)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve TEXT PRIMARY KEY,
    vendor TEXT, product TEXT, name TEXT, description TEXT,
    date_added TEXT, due_date TEXT,
    in_kev INTEGER DEFAULT 0,
    ransomware_use TEXT,             -- KEV knownRansomwareCampaignUse: Known / Unknown
    required_action TEXT,
    cwes TEXT DEFAULT '[]',
    epss REAL, epss_percentile REAL, epss_date TEXT,
    cvss REAL, cvss_version TEXT, cvss_vector TEXT, severity TEXT,
    nvd_published TEXT,
    priority REAL, priority_parts TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS actor_records (
    source TEXT NOT NULL,            -- attack | ransomware
    source_id TEXT NOT NULL,         -- G0010 / ransomware.live group name
    name TEXT NOT NULL,
    aliases TEXT DEFAULT '[]',
    description TEXT,
    url TEXT,
    extra TEXT DEFAULT '{}',
    PRIMARY KEY (source, source_id)
);

CREATE TABLE IF NOT EXISTS actors (
    id TEXT PRIMARY KEY,             -- actor:<key>
    name TEXT NOT NULL,
    aliases TEXT DEFAULT '[]',
    kinds TEXT DEFAULT '[]',         -- ["attack-group", "ransomware"]
    attack_id TEXT,
    ransomware_name TEXT,
    description TEXT,
    url TEXT
);
CREATE TABLE IF NOT EXISTS actor_aliases (
    alias TEXT PRIMARY KEY,          -- normalised alias
    actor_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tactics (
    id TEXT PRIMARY KEY, shortname TEXT, name TEXT, ord INTEGER
);
CREATE TABLE IF NOT EXISTS techniques (
    id TEXT PRIMARY KEY, stix_id TEXT, name TEXT, tactics TEXT DEFAULT '[]',
    is_sub INTEGER DEFAULT 0, parent TEXT, description TEXT, url TEXT
);
CREATE TABLE IF NOT EXISTS software (
    id TEXT PRIMARY KEY, stix_id TEXT, name TEXT, type TEXT,
    aliases TEXT DEFAULT '[]', description TEXT, url TEXT
);

CREATE TABLE IF NOT EXISTS relationships (
    id INTEGER PRIMARY KEY,
    src TEXT NOT NULL, rel TEXT NOT NULL, dst TEXT NOT NULL,
    source TEXT NOT NULL,
    first_seen REAL,
    note TEXT,
    UNIQUE(src, rel, dst, source)
);
CREATE INDEX IF NOT EXISTS ix_rel_src ON relationships(src);
CREATE INDEX IF NOT EXISTS ix_rel_dst ON relationships(dst);

CREATE TABLE IF NOT EXISTS victims (
    id INTEGER PRIMARY KEY,
    group_name TEXT NOT NULL,
    actor_id TEXT,
    victim TEXT NOT NULL,
    domain TEXT, sector TEXT, country TEXT,
    attack_date TEXT, discovered TEXT,
    ref_url TEXT,
    UNIQUE(group_name, victim)
);
CREATE INDEX IF NOT EXISTS ix_vic_disc ON victims(discovered);

CREATE TABLE IF NOT EXISTS netblocks (
    cidr TEXT PRIMARY KEY, list TEXT, sbl_id TEXT, rir TEXT,
    start_int TEXT, end_int TEXT, version INTEGER, first_seen REAL
);

CREATE TABLE IF NOT EXISTS clusters (
    id INTEGER PRIMARY KEY,
    kind TEXT, key TEXT, size INTEGER, members TEXT, families TEXT
);

CREATE TABLE IF NOT EXISTS feed_runs (
    id INTEGER PRIMARY KEY,
    feed TEXT NOT NULL,
    started REAL, ended REAL,
    status TEXT,                     -- running | ok | cached | skipped | error | seeded
    rows INTEGER DEFAULT 0,
    error TEXT,
    mode TEXT                        -- live | fixture
);
CREATE INDEX IF NOT EXISTS ix_runs_feed ON feed_runs(feed, started);

CREATE TABLE IF NOT EXISTS feed_state (
    feed TEXT PRIMARY KEY,
    enabled_override INTEGER         -- NULL = use config file
);

CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    """Open a connection with sane defaults (WAL, row factory, busy timeout)."""
    db_path = Path(path) if path else config.get().db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.executescript(SCHEMA)
    return conn


@contextmanager
def session(path: str | Path | None = None):
    conn = connect(path)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def rows(conn: sqlite3.Connection, sql: str, params=()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def one(conn: sqlite3.Connection, sql: str, params=()) -> dict | None:
    r = conn.execute(sql, params).fetchone()
    return dict(r) if r else None


def jload(text, default=None):
    if text in (None, ""):
        return default if default is not None else []
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default if default is not None else []


def now() -> float:
    return time.time()


# ---------------------------------------------------------------- indicators

def upsert_indicator(conn, *, type: str, value: str, source: str, first_seen: float | None = None,
                     last_seen: float | None = None, tags=None, malware: str | None = None,
                     asn: int | None = None, as_name: str | None = None, country: str | None = None,
                     host: str | None = None, reg_domain: str | None = None, extra: dict | None = None) -> int:
    """Insert or merge an indicator and record the sighting for `source`."""
    ts = now()
    first_seen = first_seen or ts
    last_seen = last_seen or ts
    tags = sorted(set(tags or []))
    row = conn.execute("SELECT id, sources, tags, first_seen, last_seen FROM indicators WHERE type=? AND value=?",
                       (type, value)).fetchone()
    if row:
        ind_id = row["id"]
        sources = sorted(set(jload(row["sources"])) | {source})
        all_tags = sorted(set(jload(row["tags"])) | set(tags))
        conn.execute(
            """UPDATE indicators SET sources=?, tags=?, first_seen=MIN(COALESCE(first_seen, ?), ?),
               last_seen=MAX(COALESCE(last_seen, 0), ?), malware=COALESCE(?, malware), asn=COALESCE(?, asn),
               as_name=COALESCE(?, as_name), country=COALESCE(?, country), host=COALESCE(?, host),
               reg_domain=COALESCE(?, reg_domain) WHERE id=?""",
            (json.dumps(sources), json.dumps(all_tags), first_seen, first_seen, last_seen, malware, asn,
             as_name, country, host, reg_domain, ind_id))
    else:
        cur = conn.execute(
            """INSERT INTO indicators(type, value, first_seen, last_seen, sources, tags, malware, asn, as_name,
               country, host, reg_domain) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (type, value, first_seen, last_seen, json.dumps([source]), json.dumps(tags), malware, asn, as_name,
             country, host, reg_domain))
        ind_id = cur.lastrowid
    conn.execute(
        """INSERT INTO sightings(indicator_id, source, first_seen, last_seen, malware, tags, extra)
           VALUES (?,?,?,?,?,?,?)
           ON CONFLICT(indicator_id, source) DO UPDATE SET
             first_seen=MIN(sightings.first_seen, excluded.first_seen),
             last_seen=MAX(sightings.last_seen, excluded.last_seen),
             malware=COALESCE(excluded.malware, sightings.malware),
             tags=excluded.tags, extra=excluded.extra""",
        (ind_id, source, first_seen, last_seen, malware, json.dumps(tags), json.dumps(extra or {})))
    return ind_id


def add_rel(conn, src: str, rel: str, dst: str, source: str, note: str | None = None) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO relationships(src, rel, dst, source, first_seen, note) VALUES (?,?,?,?,?,?)",
        (src, rel, dst, source, now(), note))


# ---------------------------------------------------------------- feed runs

def start_run(conn, feed: str, mode: str = "live") -> int:
    cur = conn.execute("INSERT INTO feed_runs(feed, started, status, mode) VALUES (?,?,?,?)",
                       (feed, now(), "running", mode))
    conn.commit()
    return cur.lastrowid


def finish_run(conn, run_id: int, status: str, rows_: int = 0, error: str | None = None) -> None:
    conn.execute("UPDATE feed_runs SET ended=?, status=?, rows=?, error=? WHERE id=?",
                 (now(), status, rows_, (error or "")[:2000] or None, run_id))
    conn.commit()


def set_meta(conn, key: str, value) -> None:
    conn.execute("INSERT OR REPLACE INTO meta(k, v) VALUES (?, ?)", (key, json.dumps(value)))


def get_meta(conn, key: str, default=None):
    r = conn.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
    return json.loads(r["v"]) if r else default
