"""Console tests — the cockpit against the mock engine (TestClient, no server)."""
from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

SAMPLE_DIR = os.environ.get("SEVER_SAMPLE_DIR", "N:/HERMESSSS/graphhacks/data/ad_sample")
pytestmark = pytest.mark.skipif(
    not Path(SAMPLE_DIR).is_dir(), reason="sample data not present"
)
HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("SEVER_BACKEND", "mock")
    monkeypatch.setenv("SEVER_SAMPLE_DIR", SAMPLE_DIR)
    import sever.console.app as appmod

    importlib.reload(appmod)
    return TestClient(appmod.app)


def test_index_serves_the_console(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "SEVER" in r.text


def test_state_starts_clean(client):
    r = client.get("/api/state")
    assert r.status_code == 200
    body = r.json()
    assert body["backend"] == "mock"
    assert body["reachability"] == 0
    assert len(body["jewels"]) == 5


def test_breach_finding_raises_surface(client):
    r = client.post("/api/finding", json={"kind": "credential_breach", "subject": HERO})
    assert r.status_code == 200
    body = r.json()
    assert "T1078.002" in body["technique"]
    assert body["reachability"] == 1
    paths = client.get("/api/paths").json()
    assert paths["paths"]


def test_human_gate_403_without_approval(client):
    client.post("/api/finding", json={"kind": "credential_breach", "subject": HERO})
    prop = client.get("/api/proposal").json()
    top = prop[0]
    r = client.post("/api/cut", json={
        "src": top["src"], "dst": top["dst"], "rel": top["rel"], "approved": False,
    })
    assert r.status_code == 403


def test_approved_cut_collapses_via_console(client):
    client.post("/api/finding", json={"kind": "credential_breach", "subject": HERO})
    prop = client.get("/api/proposal").json()
    top = prop[0]
    r = client.post("/api/cut", json={
        "src": top["src"], "dst": top["dst"], "rel": top["rel"],
        "approved": True, "approved_by": "console-operator",
    })
    assert r.status_code == 200
    receipt = r.json()
    assert receipt["approved_by"] == "console-operator"
    state = client.get("/api/state").json()
    assert state["reachability"] == 0
    recs = client.get("/api/receipts").json()
    assert any(e.get("step") == "cut" for e in recs)
