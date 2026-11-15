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
- History: each sighting also keeps first_obs / last_obs (when this lab first and
  last saw the indicator in that feed, across runs) and days_seen. A daily
  snapshot of key counts goes to `daily_snapshot` after every correlation run,
  so trends survive even when bulk lists are pruned (see prune_source).
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

CREATE TABLE IF NOT EXISTS daily_snapshot (
    day TEXT NOT NULL,               -- YYYY-MM-DD (UTC)
    metric TEXT NOT NULL,            -- e.g. indicators, c2_ips, source:cins, phishing_branded
    value REAL,
    PRIMARY KEY (day, metric)
);

CREATE TABLE IF NOT EXISTS misp_events (
    uuid TEXT PRIMARY KEY,
    source TEXT NOT NULL,            -- circl
    info TEXT, date TEXT, org TEXT,
    threat_level INTEGER,
    tags TEXT DEFAULT '[]',
    timestamp REAL,
    attributes INTEGER DEFAULT 0,    -- attributes in the event
    stored INTEGER DEFAULT 0         -- attributes kept as indicators
);

CREATE TABLE IF NOT EXISTS rdap (
    key TEXT PRIMARY KEY,            -- domain:<registered domain> | ip:<address>
    kind TEXT, query TEXT,
    status TEXT,                     -- ok | not-found | no-service | error
    registered TEXT, expires TEXT, last_changed TEXT,
    registrar TEXT, abuse_email TEXT, abuse_phone TEXT,
    network TEXT, country TEXT, statuses TEXT DEFAULT '[]',
    server TEXT, error TEXT,
    fetched_at REAL
);

CREATE TABLE IF NOT EXISTS phishing_analysis (
    indicator_id INTEGER PRIMARY KEY,
    score INTEGER, brands TEXT DEFAULT '[]', method TEXT,
    reasons TEXT DEFAULT '[]', tld TEXT, idn INTEGER DEFAULT 0,
    keyword_brands TEXT DEFAULT '[]' -- what the old keyword-only matcher found (for before/after)
);
"""

# Columns added after the first release; connect() adds them to older databases.
MIGRATIONS = {
    "sightings": {"first_obs": "REAL", "last_obs": "REAL", "days_seen": "INTEGER DEFAULT 0", "last_day": "TEXT"},
}


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
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    for table, cols in MIGRATIONS.items():
        have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        missing = {c: t for c, t in cols.items() if c not in have}
        for col, typ in missing.items():
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
        if table == "sightings" and "first_obs" in missing:
            # Older databases: the best estimate of "first observed by this lab" is the
            # first successful run of that feed, else the feed's own first_seen.
            conn.execute("""UPDATE sightings SET
                first_obs = COALESCE((SELECT MIN(started) FROM feed_runs WHERE feed=sightings.source
                                      AND status IN ('ok','cached','seeded','stale')), first_seen),
                last_obs = COALESCE((SELECT MAX(started) FROM feed_runs WHERE feed=sightings.source
                                     AND status IN ('ok','cached','seeded','stale')), last_seen),
                days_seen = 1""")
            conn.execute("UPDATE sightings SET last_day = strftime('%Y-%m-%d', last_obs, 'unixepoch')")
            conn.commit()
    conn.execute("CREATE INDEX IF NOT EXISTS ix_sight_obs ON sightings(source, first_obs)")


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
                     host: str | None = None, reg_domain: str | None = None, extra: dict | None = None,
                     observed_at: float | None = None) -> int:
    """Insert or merge an indicator and record the sighting for `source`.

    observed_at is when this lab saw it (default now); it feeds first_obs/last_obs
    and days_seen, which are independent of the dates the feed itself reports.
    """
    ts = now()
    obs = observed_at or ts
    obs_day = time.strftime("%Y-%m-%d", time.gmtime(obs))
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
        """INSERT INTO sightings(indicator_id, source, first_seen, last_seen, malware, tags, extra,
                                 first_obs, last_obs, days_seen, last_day)
           VALUES (?,?,?,?,?,?,?,?,?,1,?)
           ON CONFLICT(indicator_id, source) DO UPDATE SET
             first_seen=MIN(sightings.first_seen, excluded.first_seen),
             last_seen=MAX(sightings.last_seen, excluded.last_seen),
             malware=COALESCE(excluded.malware, sightings.malware),
             tags=excluded.tags, extra=excluded.extra,
             first_obs=MIN(COALESCE(sightings.first_obs, excluded.first_obs), excluded.first_obs),
             last_obs=MAX(COALESCE(sightings.last_obs, 0), excluded.last_obs),
             days_seen=COALESCE(sightings.days_seen, 0) +
                       (COALESCE(sightings.last_day, '') < excluded.last_day),
             last_day=MAX(COALESCE(sightings.last_day, ''), excluded.last_day)""",
        (ind_id, source, first_seen, last_seen, malware, json.dumps(tags), json.dumps(extra or {}),
         obs, obs, obs_day))
    return ind_id


def prune_source(conn, source: str, keep_days: float, ref: float | None = None) -> int:
    """Drop `source` sightings not observed for keep_days, then indicators left with no sightings.

    Used for large rotating lists (CINS, blocklist.de, phishing.army) so the database
    does not grow without bound. Daily counts already captured in daily_snapshot stay.
    Returns the number of indicators deleted.
    """
    cutoff = (ref or now()) - keep_days * 86400
    stale = [r[0] for r in conn.execute("SELECT indicator_id FROM sightings WHERE source=? AND last_obs < ?",
                                        (source, cutoff))]
    if not stale:
        return 0
    conn.executemany("DELETE FROM sightings WHERE indicator_id=? AND source=?", [(i, source) for i in stale])
    gone = [i for i in stale if not conn.execute("SELECT 1 FROM sightings WHERE indicator_id=? LIMIT 1", (i,)).fetchone()]
    for i in gone:
        row = conn.execute("SELECT type, value FROM indicators WHERE id=?", (i,)).fetchone()
        if row:
            node = f"{row['type']}:{row['value']}"
            conn.execute("DELETE FROM relationships WHERE (src=? OR dst=?) AND source=?", (node, node, source))
        conn.execute("DELETE FROM indicators WHERE id=?", (i,))
        conn.execute("DELETE FROM phishing_analysis WHERE indicator_id=?", (i,))
    # indicators still reported by another feed lose this source from their list
    for i in set(stale) - set(gone):
        row = conn.execute("SELECT sources FROM indicators WHERE id=?", (i,)).fetchone()
        if row:
            conn.execute("UPDATE indicators SET sources=? WHERE id=?",
                         (json.dumps(sorted(set(jload(row["sources"])) - {source})), i))
    return len(gone)


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
