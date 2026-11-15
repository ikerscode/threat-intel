"""Terminal HUD spec: every view answers, every action maps to a real route, clean() strips escapes."""
import re

import pytest
from fastapi.testclient import TestClient

from threatintel import termhud
from threatintel.tui_spec import SPEC

HOST = {"host": "127.0.0.1"}


@pytest.fixture(scope="module")
def client(seeded):
    from threatintel.server import app
    with TestClient(app) as c:
        yield c


def _route_exists(method: str, endpoint: str) -> bool:
    from threatintel.server import app
    concrete = re.sub(r"\{[\w.]+\}", "x", endpoint.split("?", 1)[0])
    return any(method in getattr(route, "methods", set()) and route.path_regex.match(concrete)
               for route in app.routes)


def test_spec_shape():
    assert SPEC["title"] == "THREAT-INTEL"
    assert 3 <= len(SPEC["views"]) <= 9
    keys = [a["key"] for a in SPEC["actions"]]
    assert len(keys) == len(set(keys))
    for key in keys:
        assert len(key) == 1 and key.isalpha() and key != "q", key


@pytest.mark.parametrize("view", SPEC["views"], ids=lambda v: v["name"])
def test_view_endpoints_answer(client, view):
    r = client.get(view["endpoint"], headers=HOST)
    assert r.status_code == 200, view["endpoint"]
    if "rows" in view:
        assert isinstance(termhud.dig(r.json(), view["rows"]), list)
        detail = view.get("detail")
        rows = termhud.dig(r.json(), view["rows"])
        if detail and rows:
            filled = termhud._fill(detail, rows[0])
            assert client.get(filled, headers=HOST).status_code == 200, filled


@pytest.mark.parametrize("action", SPEC["actions"], ids=lambda a: a["key"])
def test_action_endpoints_are_routes(action):
    assert _route_exists(action.get("method", "POST"), action["endpoint"]), action["endpoint"]


def test_clean_strips_clear_screen_escape():
    out = termhud.clean("\x1b[2Jhello")
    assert "\x1b" not in out
    assert "\x1b[2J" not in out
    assert out == "?[2Jhello"
