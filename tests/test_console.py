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


# NOTE on the 400-contract tests below: they are NOT DB-free-testable —
# sever.console.app builds a FalkorGraphPort at import time (module-level
# `app = build_app()`), so the whole console module is engine-gated like the
# rest of this file. The contract itself is documented here and pinned on
# the REAL engine: an INVALID rel in /api/finding or /api/cut flows into
# FalkorGraphPort.add_edge/cut, whose injection guard raises ValueError
# BEFORE any Cypher interpolation — the routes surface that as 400 (client
# error), not an unhandled 500 with a stack trace.


def test_finding_with_invalid_rel_is_rejected_400_not_500(client):
    before = client.get("/api/state").json()
    r = client.post("/api/finding", json={
        "kind": "ace_granted", "subject": HERO, "target": "S-1-5-21-t-9999",
        "rel": "member_of",  # lowercase -> rejected by the closed rel vocabulary
    })
    assert r.status_code == 400
    assert "invalid relationship type" in r.json()["detail"]
    # nothing reached the graph
    after = client.get("/api/state").json()
    assert after["edges"] == before["edges"]
    assert after["reachability"] == before["reachability"]


def test_cut_with_invalid_rel_is_rejected_400_not_500(client):
    client.post("/api/finding", json={"kind": "credential_breach", "subject": HERO})
    r = client.post("/api/cut", json={
        "src": HERO, "dst": "S-1-5-21-t-9999",
        "rel": "x'); MATCH (n) DETACH DELETE n",  # injection attempt
        "approved": True,  # past the human gate
    })
    # audit2/api-contract: a syntax violation is now caught by the wired
    # request schema (REL_PATTERN) as 422 BEFORE the handler — the engine's
    # vocabulary guard never sees it. The 400 vocabulary contract lives on
    # for well-formed unknown rels (see test_injection_rels_die_at_schema_layer_422
    # and test_finding_with_invalid_rel_is_rejected_400_not_500).
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "string_pattern_mismatch"
    assert client.get("/api/state").json()["reachability"] == 1  # graph intact


# ---- audit2/api-contract regression: schema contract over the live engine ----

def test_gate_rejects_truthy_non_bool_approval(client):
    """/api/cut executed real interdictions pre-fix: pydantic lax bool coerced
    1/1.0/"true"/"yes"/"on"/"1" to True and the 403 gate never fired."""
    for bad in (1, 1.0, "true", "TRUE", "yes", "on", "1"):
        r = client.post("/api/cut", json={
            "src": HERO, "dst": "S-1-5-21-t-9999", "rel": "MEMBER_OF", "approved": bad,
        })
        assert r.status_code == 422, bad
        assert r.json()["detail"][0]["type"] == "bool_type"
    assert client.get("/api/state").json()["edges"]  # engine untouched


def test_injection_rels_die_at_schema_layer_422(client):
    """schemas are wired: hostile rels never reach the handler (422, not the
    port-level 400); the 400 remains the vocabulary gate for well-formed
    unknown rels."""
    r = client.post("/api/cut", json={
        "src": HERO, "dst": "S-1-5-21-t-9999", "rel": "MEMBER_OF\n", "approved": True,
    })
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "string_pattern_mismatch"
    r = client.post("/api/cut", json={
        "src": HERO, "dst": "S-1-5-21-t-9999",
        "rel": "x'); MATCH (n) DETACH DELETE n //", "approved": True,
    })
    assert r.status_code == 422
    # well-formed but unknown rel still answers 400 (vocabulary gate)
    r = client.post("/api/cut", json={
        "src": HERO, "dst": "S-1-5-21-t-9999", "rel": "generic_all", "approved": True,
    })
    assert r.status_code == 400


def test_oversized_and_empty_fields_are_422(client):
    r = client.post("/api/finding", json={"subject": "S-1-" + "9" * 10_000})
    assert r.status_code == 422  # 100KB subject dies at the schema, not 200
    r = client.post("/api/finding", json={"subject": ""})
    assert r.status_code == 422  # empty subject is not a principal
    r = client.post("/api/cut", json={
        "src": HERO, "dst": "S-1-5-21-t-9999", "rel": "MEMBER_OF",
        "approved": True, "approved_by": "x" * 500,
    })
    assert r.status_code == 422
    r = client.post("/api/cut", json={"src": "", "dst": HERO, "rel": "MEMBER_OF", "approved": False})
    assert r.status_code == 422


def test_lone_surrogate_is_422_and_never_poisons_receipts(client):
    """Pre-fix: kind="\\ud800" 500'd the response AND wrote a ledger line that
    killed GET /api/receipts persistently (poisoned UTF-8 render)."""
    r = client.post(
        "/api/finding", content=b'{"kind": "\\ud800", "subject": "S-1"}',
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 422
    # receipts stay readable — no poisoned line in the append-only ledger
    r = client.get("/api/receipts")
    assert r.status_code == 200
    assert client.get("/api/state").status_code == 200


def test_unapproved_cut_leaves_no_cut_receipt(client):
    client.post("/api/finding", json={"kind": "credential_breach", "subject": HERO})
    cuts_before = [e for e in client.get("/api/receipts").json() if e.get("step") == "cut"]
    r = client.post("/api/cut", json={
        "src": HERO, "dst": "S-1-5-21-t-9999", "rel": "MEMBER_OF", "approved": False,
    })
    assert r.status_code == 403
    cuts_after = [e for e in client.get("/api/receipts").json() if e.get("step") == "cut"]
    assert len(cuts_after) == len(cuts_before)  # a refused cut never enters the ledger


def test_gate_403_only_for_wellformed_requests(client):
    """Gate ordering: a well-formed but unapproved request gets 403; a
    schema-invalid one gets 422 before the gate can answer."""
    r = client.post("/api/cut", json={
        "src": HERO, "dst": "S-1-5-21-t-9999", "rel": "MEMBER_OF", "approved": False,
    })
    assert r.status_code == 403
    r = client.post("/api/cut", json={
        "src": HERO, "dst": "S-1-5-21-t-9999", "rel": "MEMBER_OF\n", "approved": False,
    })
    assert r.status_code == 422
