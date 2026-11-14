"""Test setup: every test session gets its own temporary database, cache and report folder.

Tests never touch the network. The seeded database is built once from fixtures/.
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session", autouse=True)
def isolated_env(tmp_path_factory):
    base = tmp_path_factory.mktemp("ti")
    os.environ["TI_DB"] = str(base / "ti.db")
    os.environ["TI_CACHE"] = str(base / "cache")
    os.environ["TI_REPORTS"] = str(base / "reports")
    os.environ.pop("ABUSECH_AUTH_KEY", None)
    os.environ.pop("NVD_API_KEY", None)
    from threatintel import asn, config
    config.reset()
    asn.reload()
    yield base


@pytest.fixture(scope="session")
def seeded(isolated_env):
    from threatintel import seed
    stats = seed.run(fresh=True)
    return stats


@pytest.fixture()
def conn(seeded):
    from threatintel import db
    c = db.connect()
    yield c
    c.close()
