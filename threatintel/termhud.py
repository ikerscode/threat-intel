"""termhud: a small terminal dashboard driven by a declarative spec.

Standard library only (curses + urllib). A project describes its views and
actions in a SPEC dict; this module draws them and talks to the project's local
HTTP API. Usage from a project:

    from .termhud import run
    run(SPEC, base_url="http://127.0.0.1:8101")

SPEC format
-----------
{
  "title": "MALWARE-LAB",
  "views": [                                  # switched with 1..9 / Tab
    {"name": "Samples", "endpoint": "/api/samples",
     "rows": "samples",                       # dotted path to a list in the JSON (omit for a dict view)
     "columns": [["sha256", 12], ["verdict", 10], ["category", 16]],   # [field (dotted ok), width]
     "detail": "/api/samples/{sha256}"},      # Enter on a row opens this (fields from the row)
    {"name": "Status", "endpoint": "/api/overview"},   # no "rows": shown as key/value lines
  ],
  "actions": [                                # global hot keys
    {"key": "r", "label": "run specimens", "method": "POST", "endpoint": "/api/specimens/run",
     "body": {"name": "all"}, "confirm": true},
  ],
  "refresh": 5,                               # seconds between automatic refreshes
}

Keys: 1-9/Tab switch view, Up/Down/PgUp/PgDn move, Enter open detail, Esc/Backspace back,
r refresh (unless bound to an action), action keys as listed in the footer, q quit.

Every string shown comes from data that may be attacker-controlled (honeypot logins,
phishing URLs, malware strings), so control characters and escape sequences are
stripped before anything reaches the terminal.
"""
from __future__ import annotations

import curses
import json
import re
import sys
import time
import urllib.error
import urllib.request

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
TIMEOUT = 10          # reads
ACTION_TIMEOUT = 180  # actions such as scenario runs or training can take minutes


def clean(value) -> str:
    """Printable, single-line text for the terminal (no escape sequences)."""
    if value is None:
        return "-"
    if isinstance(value, float):
        value = f"{value:.4g}"
    elif isinstance(value, (list, tuple)):
        value = ", ".join(clean(v) for v in value)
    elif isinstance(value, dict):
        value = json.dumps(value, default=str)
    return _CONTROL.sub("?", str(value).replace("\n", " ").replace("\t", " "))


def dig(obj, path: str | None):
    """Follow a dotted path through dicts/lists; '' or None returns obj."""
    if not path:
        return obj
    for part in path.split("."):
        if isinstance(obj, dict):
            obj = obj.get(part)
        elif isinstance(obj, list) and part.isdigit() and int(part) < len(obj):
            obj = obj[int(part)]
        else:
            return None
    return obj


def flatten(obj, prefix: str = "", depth: int = 0, out: list | None = None) -> list[tuple[str, str]]:
    """Nested JSON -> indented (key, value) lines for the detail and dict views."""
    out = [] if out is None else out
    pad = "  " * depth
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)) and v and depth < 4 and not _is_scalar_list(v):
                out.append((pad + clean(k), ""))
                flatten(v, prefix, depth + 1, out)
            else:
                out.append((pad + clean(k), clean(v)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:200]):
            if isinstance(v, (dict, list)) and depth < 4:
                out.append((pad + f"[{i}]", ""))
                flatten(v, prefix, depth + 1, out)
            else:
                out.append((pad + f"[{i}]", clean(v)))
        if len(obj) > 200:
            out.append((pad + "...", f"{len(obj) - 200} more"))
    else:
        out.append((pad + "value", clean(obj)))
    return out


def _is_scalar_list(v) -> bool:
    return isinstance(v, list) and len(v) <= 12 and all(not isinstance(x, (dict, list)) for x in v)


class Client:
    """Minimal JSON client for the project's localhost API."""

    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")

    def call(self, method: str, path: str, body=None, timeout: float = TIMEOUT):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"HTTP {e.code}: {clean(e.read()[:200].decode('utf-8', 'replace'))}") from None
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            raise RuntimeError(f"cannot reach {self.base} ({clean(getattr(e, 'reason', e))}); is ./run.sh running?") from None
        try:
            return json.loads(raw)
        except ValueError:
            return {"text": raw[:4000].decode("utf-8", "replace")}


def _fill(template: str, row: dict) -> str:
    from urllib.parse import quote
    return re.sub(r"\{([\w.]+)\}", lambda m: quote(clean(dig(row, m.group(1))), safe=""), template)


class App:
    def __init__(self, spec: dict, client: Client):
        self.spec, self.client = spec, client
        self.views = spec["views"]
        self.actions = {a["key"]: a for a in spec.get("actions", [])}
        self.view = 0
        self.rows: list = []
        self.lines: list[tuple[str, str]] = []
        self.sel = self.top = 0
        self.detail: tuple[str, list] | None = None  # (title, lines)
        self.dtop = 0
        self.status = ""
        self.last = 0.0

    # ---------------------------------------------------------------- data
    def load(self):
        v = self.views[self.view]
        try:
            data = self.client.call("GET", v["endpoint"])
            if "rows" in v:
                rows = dig(data, v["rows"])
                self.rows = rows if isinstance(rows, list) else []
                self.sel = min(self.sel, max(len(self.rows) - 1, 0))
            else:
                self.lines = flatten(dig(data, v.get("path")))
            self.status = time.strftime("updated %H:%M:%S")
        except RuntimeError as e:
            self.rows, self.lines, self.status = [], [], str(e)
        self.last = time.time()

    def open_detail(self):
        v = self.views[self.view]
        if "rows" not in v or not self.rows:
            return
        row = self.rows[self.sel]
        try:
            data = self.client.call("GET", _fill(v["detail"], row)) if v.get("detail") else row
        except RuntimeError as e:
            self.status = str(e)
            return
        self.detail, self.dtop = (clean(v["name"]) + " detail", flatten(data)), 0

    def run_action(self, scr, a: dict):
        if a.get("confirm") and not self.confirm(scr, f"{a['label']}? [y/N]"):
            self.status = "cancelled"
            return
        row = self.rows[self.sel] if self.rows and "rows" in self.views[self.view] else {}
        self.status = f"{a['label']}..."
        self.draw(scr)
        try:
            res = self.client.call(a.get("method", "POST"), _fill(a["endpoint"], row), a.get("body"),
                                   timeout=ACTION_TIMEOUT)
            self.detail, self.dtop = (clean(a["label"]) + " result", flatten(res)), 0
            self.status = f"{a['label']}: done"
        except RuntimeError as e:
            self.status = f"{a['label']}: {e}"
        self.load()

    def confirm(self, scr, prompt: str) -> bool:
        h, w = scr.getmaxyx()
        scr.addnstr(h - 1, 0, prompt.ljust(w - 1), w - 1, curses.A_REVERSE)
        scr.timeout(-1)
        ch = scr.getch()
        scr.timeout(500)
        return ch in (ord("y"), ord("Y"))

    # ---------------------------------------------------------------- drawing
    def draw(self, scr):
        scr.erase()
        h, w = scr.getmaxyx()
        if h < 6 or w < 30:
            scr.addnstr(0, 0, "terminal too small", w - 1)
            scr.refresh()
            return
        tabs = "  ".join(f"{i + 1}:{v['name']}" for i, v in enumerate(self.views))
        head = f" {self.spec['title']}  {self.client.base}  | {tabs}"
        scr.addnstr(0, 0, head.ljust(w - 1), w - 1, curses.A_REVERSE)
        body_h = h - 3
        if self.detail:
            self._draw_lines(scr, self.detail[1], self.dtop, body_h, title=self.detail[0])
        elif "rows" in self.views[self.view]:
            self._draw_table(scr, body_h, w)
        else:
            self._draw_lines(scr, self.lines, self.dtop, body_h, title=self.views[self.view]["name"])
        keys = "  ".join(f"{k}:{a['label']}" for k, a in self.actions.items())
        foot = "q quit  Tab view  Enter open  Esc back" + (f"  | {keys}" if keys else "")
        scr.addnstr(h - 2, 0, foot.ljust(w - 1), w - 1, curses.A_DIM)
        scr.addnstr(h - 1, 0, clean(self.status).ljust(w - 1), w - 1)
        scr.refresh()

    def _draw_table(self, scr, body_h, w):
        cols = self.views[self.view]["columns"]
        header = " ".join(clean(c).upper()[:n].ljust(n) for c, n in cols)
        scr.addnstr(1, 0, header, w - 1, curses.A_BOLD)
        if not self.rows:
            scr.addnstr(2, 0, "(no rows)", w - 1, curses.A_DIM)
            return
        visible = body_h - 1
        if self.sel < self.top:
            self.top = self.sel
        elif self.sel >= self.top + visible:
            self.top = self.sel - visible + 1
        for i, row in enumerate(self.rows[self.top:self.top + visible]):
            line = " ".join(clean(dig(row, c))[:n].ljust(n) for c, n in cols)
            attr = curses.A_REVERSE if self.top + i == self.sel else curses.A_NORMAL
            scr.addnstr(2 + i, 0, line.ljust(w - 1), w - 1, attr)
        scr.addnstr(1, max(w - 14, 0), f"{self.sel + 1}/{len(self.rows)}".rjust(12), 12, curses.A_DIM)

    def _draw_lines(self, scr, lines, top, body_h, title=""):
        h, w = scr.getmaxyx()
        scr.addnstr(1, 0, f"-- {title} --", w - 1, curses.A_BOLD)
        keyw = min(max((len(k) for k, _ in lines), default=0), max(w // 3, 10))
        for i, (k, v) in enumerate(lines[top:top + body_h - 1]):
            scr.addnstr(2 + i, 0, f"{k[:keyw].ljust(keyw)}  {v}", w - 1)

    # ---------------------------------------------------------------- loop
    def handle(self, scr, ch) -> bool:
        lines = self.detail[1] if self.detail else self.lines
        page = max(scr.getmaxyx()[0] - 5, 1)
        in_lines = self.detail or "rows" not in self.views[self.view]
        if ch in (ord("q"), ord("Q")):
            return False
        if ch in (27, curses.KEY_BACKSPACE, 127) and self.detail:
            self.detail = None
        elif ch == ord("\t") or ch == curses.KEY_RIGHT:
            self.view, self.sel, self.top, self.dtop, self.detail = (self.view + 1) % len(self.views), 0, 0, 0, None
            self.load()
        elif ch == curses.KEY_LEFT:
            self.view, self.sel, self.top, self.dtop, self.detail = (self.view - 1) % len(self.views), 0, 0, 0, None
            self.load()
        elif ord("1") <= ch <= ord("9") and ch - ord("1") < len(self.views):
            self.view, self.sel, self.top, self.dtop, self.detail = ch - ord("1"), 0, 0, 0, None
            self.load()
        elif ch in (curses.KEY_DOWN, ord("j"), curses.KEY_NPAGE, curses.KEY_UP, ord("k"), curses.KEY_PPAGE):
            step = page if ch in (curses.KEY_NPAGE, curses.KEY_PPAGE) else 1
            step = -step if ch in (curses.KEY_UP, ord("k"), curses.KEY_PPAGE) else step
            if in_lines:
                self.dtop = max(0, min(self.dtop + step, max(len(lines) - 1, 0)))
            else:
                self.sel = max(0, min(self.sel + step, len(self.rows) - 1))
        elif ch in (curses.KEY_ENTER, 10, 13) and not self.detail:
            self.open_detail()
        elif 0 <= ch < 256 and chr(ch) in self.actions:
            self.run_action(scr, self.actions[chr(ch)])
        elif ch in (ord("r"), ord("R")):
            self.load()
        return True

    def main(self, scr):
        curses.curs_set(0)
        scr.timeout(500)
        self.load()
        while True:
            if not self.detail and time.time() - self.last > self.spec.get("refresh", 5):
                self.load()
            self.draw(scr)
            if not self.handle(scr, scr.getch()):
                return


def print_once(spec: dict, client: Client) -> int:
    """Non-interactive mode: print every view once as plain text (for SSH, scripts, CI)."""
    code = 0
    for v in spec["views"]:
        print(f"== {v['name']} ({v['endpoint']})")
        try:
            data = client.call("GET", v["endpoint"])
        except RuntimeError as e:
            print(f"   error: {e}")
            code = 1
            continue
        if "rows" in v:
            rows = dig(data, v["rows"]) or []
            print(" ".join(clean(c).upper()[:n].ljust(n) for c, n in v["columns"]))
            for row in rows[:25]:
                print(" ".join(clean(dig(row, c))[:n].ljust(n) for c, n in v["columns"]))
            if len(rows) > 25:
                print(f"   ... {len(rows) - 25} more")
        else:
            for k, val in flatten(dig(data, v.get("path")))[:40]:
                print(f"{k}  {val}")
        print()
    return code


def run(spec: dict, base_url: str, once: bool = False) -> int:
    client = Client(base_url)
    if once or not sys.stdout.isatty():
        return print_once(spec, client)
    curses.wrapper(App(spec, client).main)
    return 0
