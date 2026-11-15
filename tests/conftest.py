import os

os.environ.setdefault("SECLAB_ALLOWED_HOSTS", "testserver")  # FastAPI TestClient host

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
    os.environ.pop("OTX_API_KEY", None)
    os.environ["TI_NO_KEYRING"] = "1"  # tests never read the real keyring
    from threatintel import asn, config, rdap
    config.reset()
    asn.reload()
    rdap.TRANSPORT = rdap_mock_transport()   # RDAP never reaches the network in tests
    yield base
    rdap.TRANSPORT = None


def rdap_mock_transport(log: list | None = None):
    """Serve the real bootstrap files and RDAP answers saved in fixtures/rdap-samples.json; 404 otherwise."""
    import json
    import httpx
    data = json.loads((ROOT / "fixtures" / "rdap-samples.json").read_text())
    boots = {f"https://data.iana.org/rdap/{k}.json": v for k, v in data["bootstrap"].items()}

    def handler(request):
        url = str(request.url)
        if log is not None:
            log.append(url)
        if url in boots:
            return httpx.Response(200, json=boots[url])
        if url in data["responses"]:
            return httpx.Response(200, json=data["responses"][url])
        return httpx.Response(404, json={"errorCode": 404})
    return httpx.MockTransport(handler)


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
