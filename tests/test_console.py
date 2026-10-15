"""Console tests — the cockpit against the REAL engine (TestClient)."""
from __future__ import annotations

import importlib

import pytest

from tests.conftest import requires_engine, requires_sample, drop_graph

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"
GRAPH = "sever_test_console"

pytestmark = [requires_engine, requires_sample]


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("SEVER_FALKOR_GRAPH", GRAPH)
    import sever.console.app as appmod

    importlib.reload(appmod)
    from fastapi.testclient import TestClient

    tc = TestClient(appmod.app)
    yield tc
    drop_graph(appmod.app.state.port, GRAPH)


def test_index_serves_the_console(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "SEVER" in r.text


def test_state_starts_clean(client):
    r = client.get("/api/state")
    assert r.status_code == 200
    body = r.json()
    assert body["backend"] == "falkordb"
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
