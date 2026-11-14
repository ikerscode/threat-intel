"""Command line interface: python -m threatintel <command>."""
from __future__ import annotations

import argparse
import json
import logging
import sys

from . import collectors, db


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


def cmd_seed(args) -> int:
    from . import seed
    stats = seed.run(fresh=args.fresh)
    print(json.dumps(stats, indent=2))
    return 0


def cmd_search(args) -> int:
    from . import pivot
    with db.session() as conn:
        res = pivot.search(conn, args.value, depth=args.depth)
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
    print(f"\ngraph: {len(res['graph']['nodes'])} nodes, {len(res['graph']['links'])} links")
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
    s = sub.add_parser("search", help="pivot on any value (IP, domain, URL, CVE, group, technique, malware)")
    s.add_argument("value")
    s.add_argument("--depth", type=int, default=2)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_search)
    s = sub.add_parser("brief", help="generate the intelligence brief (Markdown + HTML)")
    s.add_argument("--days", type=int, default=7)
    s.set_defaults(func=cmd_brief)
    s = sub.add_parser("export", help="write STIX 2.1 bundle and blocklists")
    s.add_argument("--out", default=None, help="output directory (default data/exports)")
    s.add_argument("--fanged", action="store_true", help="write URL/domain blocklists un-defanged (for blockers)")
    s.set_defaults(func=cmd_export)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
