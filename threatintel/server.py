"""FastAPI app: JSON API plus the static HUD at /.

Bind to 127.0.0.1 only (run.sh does this). Long jobs (feed refresh, seed,
correlate) run in background threads; the HUD polls /api/jobs for progress.
"""
from __future__ import annotations

import threading
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .localguard import LocalGuard
from . import NAME, __version__, brief, collectors, correlate, db, enrich, export, pivot, queries, rdap, scoring, seed, trends
from .config import ROOT
from .scheduler import Scheduler

STATIC = ROOT / "static"
scheduler = Scheduler()
jobs: dict[str, dict] = {}
jobs_lock = threading.Lock()


@asynccontextmanager
async def lifespan(app):
    with db.session():
        pass  # create schema
    scheduler.start()
    yield
    scheduler.stop()


app = FastAPI(title="seclab threat-intel", version=__version__, lifespan=lifespan)


app.add_middleware(LocalGuard)  # localhost-only: host allowlist, CSRF block, CSP


def run_job(kind: str, fn, *args) -> dict:
    """Start fn in a thread and return a job record the HUD can poll."""
    job_id = uuid.uuid4().hex[:10]
    job = {"id": job_id, "kind": kind, "status": "running", "started": time.time(), "result": None, "error": None}
    with jobs_lock:
        jobs[job_id] = job
        for old in sorted(jobs)[:-50] if len(jobs) > 50 else []:
            jobs.pop(old, None)

    def target():
        try:
            job["result"] = fn(*args)
            job["status"] = "done"
        except Exception as exc:  # report, do not crash the server
            job["status"], job["error"] = "error", f"{type(exc).__name__}: {exc}"
        job["ended"] = time.time()

    threading.Thread(target=target, daemon=True, name=f"job-{kind}").start()
    return job


# ------------------------------------------------------------------ basics

@app.get("/api/health")
def health():
    return {"status": "ok", "name": NAME, "version": __version__}


@app.get("/api/overview")
def overview():
    with db.session() as conn:
        data = queries.overview(conn)
    data["scheduler"] = scheduler.status()
    return data


@app.get("/api/jobs")
def list_jobs():
    with jobs_lock:
        return sorted(jobs.values(), key=lambda j: j["started"], reverse=True)[:20]


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    if job_id not in jobs:
        raise HTTPException(404, "no such job")
    return jobs[job_id]


# ------------------------------------------------------------------ feeds, seed, correlate, scheduler

@app.get("/api/feeds")
def feeds():
    with db.session() as conn:
        return {"feeds": collectors.feed_status(conn), "scheduler": scheduler.status(),
                "fixtures": seed.manifest()}


@app.get("/api/feeds/runs")
def feed_runs(feed: str = "", limit: int = Query(50, le=500)):
    with db.session() as conn:
        return queries.recent_runs(conn, feed, limit)


def _refresh(name: str, do_correlate: bool):
    with db.session() as conn:
        r = collectors.run_feed(name, conn=conn)
        if do_correlate and r.get("status") in ("ok", "stale", "cached"):
            r["correlate"] = correlate.run(conn)
        return r


@app.post("/api/feeds/{name}/refresh")
def refresh_feed(name: str, correlate_after: bool = True):
    if name not in collectors.REGISTRY:
        raise HTTPException(404, f"unknown feed {name}")
    return run_job(f"refresh:{name}", _refresh, name, correlate_after)


@app.post("/api/feeds/{name}/enable")
def enable_feed(name: str, body: dict = Body(...)):
    if name not in collectors.REGISTRY:
        raise HTTPException(404, f"unknown feed {name}")
    enabled = body.get("enabled")
    with db.session() as conn:
        collectors.set_enabled(conn, name, None if enabled is None else bool(enabled))
        return {"feed": name, "enabled": collectors.is_enabled(conn, name)}


@app.post("/api/scheduler")
def set_scheduler(body: dict = Body(...)):
    scheduler.set_enabled(bool(body.get("enabled")))
    return scheduler.status()


@app.post("/api/seed")
def do_seed(fresh: bool = False):
    return run_job("seed", seed.run, fresh)


def _correlate():
    with db.session() as conn:
        return correlate.run(conn)


@app.post("/api/correlate")
def do_correlate():
    return run_job("correlate", _correlate)


# ------------------------------------------------------------------ search / pivot

@app.get("/api/search")
def search(q: str = Query(..., min_length=1, max_length=2000), depth: int = Query(2, ge=1, le=3),
           rdap: bool = False):
    with db.session() as conn:
        return pivot.search(conn, q, depth, rdap=rdap)


@app.get("/api/rdap")
def rdap_lookup(q: str = Query(..., min_length=1, max_length=300), refresh: bool = False):
    """Registration data for a domain, URL or IP from the RDAP registry (cached; never contacts the host itself)."""
    t = rdap.target(q)
    if not t:
        raise HTTPException(400, "give a public IP address, a domain or a URL")
    with db.session() as conn:
        row = rdap.lookup(conn, q, refresh=refresh)
    return {"query": q, "target": {"kind": t[0], "value": t[1]}, "rdap": rdap.summary(row),
            "statuses": (row or {}).get("statuses", [])}


# ------------------------------------------------------------------ domain views

@app.get("/api/vulns")
def vulns(limit: int = Query(50, le=2000), ransomware: bool = False, q: str = ""):
    with db.session() as conn:
        return {"formula": scoring.VULN_FORMULA, "rows": queries.top_vulns(conn, limit, ransomware, q)}


@app.get("/api/ransomware")
def ransomware(days: int = Query(30, le=120)):
    with db.session() as conn:
        return {"anchor": queries.anchor(conn), "groups": queries.ransomware_groups(conn, 40),
                "timeline": queries.victims_timeline(conn, days),
                "sectors": queries.victim_breakdown(conn, "sector", days),
                "countries": queries.victim_breakdown(conn, "country", days),
                "recent": queries.recent_victims(conn, 40)}


@app.get("/api/infrastructure")
def infrastructure():
    with db.session() as conn:
        return {"c2_by_family": queries.c2_by_family(conn), "c2": queries.c2_list(conn, 100),
                "clusters": queries.clusters(conn), "drop_overlaps": queries.drop_overlaps(conn),
                "phishing": queries.phishing_stats(conn), "formula": scoring.INDICATOR_FORMULA,
                "by_source": queries.infrastructure_by_source(conn), "misp_events": queries.misp_events(conn, 15)}


@app.get("/api/phishing")
def phishing_view(limit: int = Query(50, le=1000), brand: str = "", min_score: int = Query(0, ge=0, le=100)):
    with db.session() as conn:
        return {"formula": scoring.PHISH_FORMULA, "summary": queries.phishing_analysis_summary(conn),
                "rows": queries.phishing_top(conn, limit, brand, min_score)}


@app.get("/api/trends")
def trends_view(days: int = Query(30, ge=1, le=365)):
    with db.session() as conn:
        return trends.trends(conn, days)


@app.get("/api/attack")
def attack(scope: str = Query("active", pattern="^(active|all)$"), limit: int = Query(40, le=300)):
    with db.session() as conn:
        return queries.technique_frequency(conn, scope, limit)


@app.get("/api/indicators")
def indicators(type: str = "", q: str = "", limit: int = Query(100, le=2000), include_context: bool = False):
    where, params = ["1=1"], []
    if type:
        where.append("type=?")
        params.append(type)
    if q:
        where.append("value LIKE ?")
        params.append(f"%{q}%")
    if not include_context:
        where.append("context_only=0")
    with db.session() as conn:
        rows = db.rows(conn, f"""SELECT type, value, confidence, sources, tags, malware, asn, country, first_seen, last_seen
                                 FROM indicators WHERE {' AND '.join(where)} ORDER BY confidence DESC LIMIT ?""",
                       (*params, limit))
    for r in rows:
        r["sources"], r["tags"] = db.jload(r["sources"]), db.jload(r["tags"])
    return rows


# ------------------------------------------------------------------ enrichment

@app.post("/api/enrich")
def do_enrich(payload: dict | list = Body(...), record: bool = False, reporter: str = "lab", rdap: bool = False):
    items = enrich.parse_payload(payload)
    if not items:
        raise HTTPException(400, "no IOCs found; send {'iocs': [...]}, {'text': '...'} or a STIX 2.1 bundle")
    with db.session() as conn:
        return enrich.enrich(conn, items, record=record, reporter=reporter, rdap=rdap)


# ------------------------------------------------------------------ exports and reports

@app.get("/api/export/stix")
def export_stix(min_confidence: int = Query(50, ge=0, le=100)):
    with db.session() as conn:
        bundle = export.stix_bundle(conn, min_confidence)
    return JSONResponse(bundle, headers={"Content-Disposition": "attachment; filename=threat-intel.stix.json"})


@app.get("/api/export/blocklist/{itype}")
def export_blocklist(itype: str, min_confidence: int = Query(50, ge=0, le=100), fanged: bool = False):
    if itype not in ("ip", "cidr", "domain", "url", "hash"):
        raise HTTPException(404, "type must be ip, cidr, domain, url or hash")
    with db.session() as conn:
        text = export.blocklist(conn, itype, min_confidence, fanged)
    return PlainTextResponse(text, headers={"Content-Disposition": f"attachment; filename=blocklist-{itype}.txt"})


@app.get("/api/export/csv")
def export_csv(min_confidence: int = Query(0, ge=0, le=100)):
    with db.session() as conn:
        text = export.indicators_csv(conn, min_confidence)
    return PlainTextResponse(text, media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=indicators.csv"})


@app.get("/api/reports")
def reports():
    return brief.list_reports()


@app.post("/api/reports")
def make_report(days: int = Query(7, ge=1, le=90)):
    with db.session() as conn:
        return brief.generate(conn, days)


@app.get("/api/reports/{name}.{fmt}")
def get_report(name: str, fmt: str, download: bool = False):
    p = brief.report_path(name, fmt)
    if not p:
        raise HTTPException(404, "no such report")
    media = "text/markdown" if fmt == "md" else "text/html"
    headers = {"Content-Disposition": f"attachment; filename={p.name}"} if download else {}
    return FileResponse(p, media_type=media, headers=headers)


@app.get("/api/formulas")
def formulas():
    return {"indicator": scoring.INDICATOR_FORMULA, "vulnerability": scoring.VULN_FORMULA, "phishing": scoring.PHISH_FORMULA,
            "source_weights": scoring.SOURCE_WEIGHTS, "half_life_days": scoring.HALF_LIFE_DAYS}


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return PlainTextResponse("", status_code=204)


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
