"""Command line interface: python -m threatintel <command>."""
from __future__ import annotations

import argparse
import json
import logging
import sys

from . import collectors, db, secrets


def cmd_collect(args) -> int:
    names = list(collectors.REGISTRY) if args.feed in (None, "all") else [args.feed]
    with db.session() as conn:
        for name in names:
            if args.feed in (None, "all") and not collectors.is_enabled(conn, name):
                print(f"{name:<11} disabled (config/feeds.toml or HUD override)")
                continue
            r = collectors.run_feed(name, conn=conn)
            dur = (r.get("ended") or 0) - (r.get("started") or 0)
            print(f"{name:<11} {r['status']:<8} rows={r.get('rows', 0):<6} {dur:6.1f}s  {(r.get('error') or '')[:150]}")
    if args.correlate:
        return cmd_correlate(args)
    return 0


def cmd_correlate(args) -> int:
    from . import correlate
    with db.session() as conn:
        stats = correlate.run(conn)
    print(json.dumps(stats, indent=2))
    return 0


def cmd_tui(args) -> int:
    from . import termhud
    from .tui_spec import SPEC
    return termhud.run(SPEC, args.url, args.once)


def cmd_seed(args) -> int:
    from . import seed
    stats = seed.run(fresh=args.fresh)
    print(json.dumps(stats, indent=2))
    return 0


def cmd_search(args) -> int:
    from . import pivot
    with db.session() as conn:
        res = pivot.search(conn, args.value, depth=args.depth, rdap=args.rdap)
    if args.json:
        print(json.dumps(res, indent=2, default=str))
        return 0
    print(f"query: {res['query']}  kind: {res['kind']}")
    if not res["found"]:
        print("no match")
        return 1
    print("entity:", json.dumps(res["entity"], default=str)[:600])
    for section, items in res["linked"].items():
        if items:
            print(f"\n[{section}] ({len(items)})")
            for it in items[:15]:
                print("  ", json.dumps(it, default=str)[:200])
    if res.get("rdap"):
        print("\nrdap:", json.dumps(res["rdap"], default=str))
    print(f"\ngraph: {len(res['graph']['nodes'])} nodes, {len(res['graph']['links'])} links")
    return 0


def cmd_rdap(args) -> int:
    """RDAP lookups for one or more values (registry servers only, cached)."""
    from . import rdap
    with db.session() as conn:
        values = list(args.values)
        if args.top_phishing:
            values += [r["reg_domain"] for r in db.rows(conn, """SELECT i.reg_domain, MAX(pa.score) s FROM phishing_analysis pa
                       JOIN indicators i ON i.id=pa.indicator_id WHERE i.reg_domain IS NOT NULL AND i.reg_domain LIKE '%[.]%'
                       GROUP BY i.reg_domain ORDER BY s DESC LIMIT ?""", (args.top_phishing * 3,))]
            values = [v for v in values if rdap.target(v)][: len(args.values) + args.top_phishing]
        rows = rdap.lookup_many(conn, values, limit=len(values) + 1)
    for key, row in rows.items():
        s = rdap.summary(row)
        print(f"{key:<45} {s['status']:<10} {(s['registered'] or '')[:10]:<11} {(s['registrar'] or s['network'] or '')[:40]:<41} {s['abuse_email'] or ''}")
    return 0


def cmd_trends(args) -> int:
    from . import trends
    with db.session() as conn:
        t = trends.trends(conn, args.days)
    print(json.dumps(t if args.json else {k: t[k] for k in ("baseline_day", "history_days", "daily")}, indent=2, default=str))
    return 0


def cmd_brief(args) -> int:
    from . import brief
    with db.session() as conn:
        out = brief.generate(conn, days=args.days)
    print(f"markdown: {out['md_path']}\nhtml:     {out['html_path']}")
    return 0


def cmd_export(args) -> int:
    from . import export
    with db.session() as conn:
        paths = export.write_all(conn, args.out, fanged=args.fanged)
    for p in paths:
        print(p)
    return 0


def cmd_set_key(args) -> int:
    """Store an API key in the desktop keyring (prompted, never echoed or logged)."""
    import getpass
    from . import secrets
    if args.delete:
        print("deleted" if secrets.delete(args.name) else "nothing stored")
        return 0
    value = getpass.getpass(f"{args.name}: ").strip()
    if not value:
        print("empty key, nothing stored")
        return 1
    secrets.store(args.name, value)
    print(f"{args.name} stored in the keyring")
    return 0


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    p = argparse.ArgumentParser(prog="python -m threatintel", description="seclab threat intelligence lab")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seed", help="load the bundled offline fixtures and correlate")
    s.add_argument("--fresh", action="store_true", help="delete the database first")
    s.set_defaults(func=cmd_seed)
    s = sub.add_parser("collect", help="run live collectors: a feed name or 'all'")
    s.add_argument("feed", nargs="?", default="all", choices=["all", *collectors.REGISTRY])
    s.add_argument("--correlate", action="store_true", help="run correlation afterwards")
    s.set_defaults(func=cmd_collect)
    s = sub.add_parser("correlate", help="merge aliases, link entities, score, cluster")
    s.set_defaults(func=cmd_correlate)
    s = sub.add_parser("tui", help="terminal HUD over the local API (1-9/Tab views, Enter detail, q quit)")
    s.add_argument("--url", default="http://127.0.0.1:8102", help="API base URL (default 127.0.0.1:8102)")
    s.add_argument("--once", action="store_true", help="print every view as plain text and exit")
    s.set_defaults(func=cmd_tui)
    s = sub.add_parser("search", help="pivot on any value (IP, domain, URL, CVE, group, technique, malware)")
    s.add_argument("value")
    s.add_argument("--depth", type=int, default=2)
    s.add_argument("--json", action="store_true")
    s.add_argument("--rdap", action="store_true", help="also look the domain/IP up in RDAP (registry only)")
    s.set_defaults(func=cmd_search)
    s = sub.add_parser("rdap", help="RDAP registration lookup (registry servers only, never the host itself)")
    s.add_argument("values", nargs="*")
    s.add_argument("--top-phishing", type=int, default=0, metavar="N",
                   help="also look up the N highest-scoring phishing registered domains")
    s.set_defaults(func=cmd_rdap)
    s = sub.add_parser("trends", help="daily history and new-per-day trends")
    s.add_argument("--days", type=int, default=30)
    s.add_argument("--json", action="store_true", help="every trend table, not just the daily one")
    s.set_defaults(func=cmd_trends)
    s = sub.add_parser("brief", help="generate the intelligence brief (Markdown + HTML)")
    s.add_argument("--days", type=int, default=7)
    s.set_defaults(func=cmd_brief)
    s = sub.add_parser("export", help="write STIX 2.1 bundle and blocklists")
    s.add_argument("--out", default=None, help="output directory (default data/exports)")
    s.add_argument("--fanged", action="store_true", help="write URL/domain blocklists un-defanged (for blockers)")
    s.set_defaults(func=cmd_export)
    s = sub.add_parser("set-key", help="store an API key in the desktop keyring (encrypted at rest)")
    s.add_argument("name", choices=list(secrets.KNOWN_KEYS))
    s.add_argument("--delete", action="store_true", help="remove the stored key")
    s.set_defaults(func=cmd_set_key)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
