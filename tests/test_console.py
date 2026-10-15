"""Console tests — the cockpit against the REAL engine (TestClient)."""
from __future__ import annotations

import importlib

import pytest

from tests.conftest import requires_engine, requires_sample, drop_graph

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"
GMSA = "S-1-5-21-2697957641-2271029196-387917394-2102"
GRAPH = "sever_test_console"

pytestmark = [requires_engine, requires_sample]


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("SEVER_FALKOR_GRAPH", GRAPH)
    # hermetic start (audit3/test-forensics flakiness sweep): build_app only
    # loads a sample into an EMPTY key, so a leftover graph from a crashed
    # previous run would silently serve stale engine state to every test in
    # this module — and the append-only receipts ledger (out/cases/*.jsonl)
    # persists a poisoned line across runs, 500ing every later /api/receipts
    # read (proven live during the mutation pass).
    from sever.core.falkor_port import FalkorGraphPort
    from sever.memory.flow import CaseLog

    drop_graph(FalkorGraphPort(graph_name=GRAPH), GRAPH)
    CaseLog(GRAPH).path.unlink(missing_ok=True)
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
    assert "SIMULATED ESTATE" in r.text  # honesty chip ships with the UI


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
    assert body["simulated"] is True  # replay findings are labeled, never passed off as live telemetry
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
        "kind": "ace_granted", "subject": HERO, "target": GMSA,
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
    assert isinstance(r.json(), list)  # ledger intact JSON — not just a 200
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




def test_cut_handler_gate_is_identity_checked_past_the_schema(client):
    """Defense-in-depth, pinned (audit3 mutation M13 flipped the handler's
    ``is not True`` to truthiness and ZERO tests noticed — the StrictBool
    schema was the only thing standing between ``approved: 1`` and this
    layer). The handler's own gate must 403 even for a value that could only
    arrive by bypassing pydantic (model_construct): identity, not truthiness.
    On a truthiness gate the request would instead fall through to the
    investigator's ValueError -> 400, so this test tells the two apart."""
    import asyncio

    from sever.console.app import app as fastapp
    from sever.console.schemas import CutRequest

    route = next(r for r in fastapp.routes if getattr(r, "path", "") == "/api/cut")
    sneaky = CutRequest.model_construct(
        src=HERO, dst="S-1-5-21-t-9999", rel="MEMBER_OF", approved=1, approved_by="x",
    )
    with pytest.raises(Exception) as ei:
        asyncio.run(route.endpoint(sneaky))
    assert getattr(ei.value, "status_code", None) == 403, (
        "the handler gate must reject non-True by IDENTITY, not truthiness"
    )


# ---- audit3/pentest-external: client-side hardening + opt-in docs ----

def test_security_headers_on_every_response(client):
    """Public deployment shipped none of these (verified against
    sever-console.onrender.com). The middleware fences clickjacking,
    MIME-sniffing, referrer leakage and pins HTTPS for proxied deploys."""
    r = client.get("/api/state")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["Strict-Transport-Security"] == "max-age=31536000"
    # fail-closed CORS posture: no origin is ever allowed to read the API
    assert "Access-Control-Allow-Origin" not in r.headers
    assert "Access-Control-Allow-Credentials" not in r.headers


def test_cors_preflight_is_not_answered(client):
    """No CORSMiddleware => a cross-origin preflight gets 405 and no
    Access-Control-Allow-* headers: other origins can neither read nor
    pre-flight a mutation."""
    r = client.options("/api/cut", headers={
        "Origin": "https://evil.example",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
    })
    assert r.status_code == 405
    assert "Access-Control-Allow-Origin" not in r.headers


def test_docs_and_schema_are_opt_in_via_sever_docs(client, monkeypatch):
    """/docs, /redoc, /openapi.json answered 200 on the public deployment —
    a complete API-map handed to any visitor. They are now off unless
    SEVER_DOCS=1."""
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404

    monkeypatch.setenv("SEVER_DOCS", "1")
    import sever.console.app as appmod

    importlib.reload(appmod)
    from fastapi.testclient import TestClient

    tc = TestClient(appmod.app)
    assert tc.get("/docs").status_code == 200
    assert tc.get("/openapi.json").status_code == 200
    assert "SEVER console" in tc.get("/openapi.json").json()["info"]["title"]


# ---- audit3/console-logic: honest rejection + verdict semantics ----

def test_unknown_finding_kind_is_422_not_a_fabricated_attck_label(client):
    """Pre-fix (live-verified): kind='totally_unknown_kind' answered 200 with
    a FABRICATED 'T1595.002 Vulnerability Scanning' technique and wrote a
    phantom finding to the receipts ledger."""
    r = client.post("/api/finding", json={"kind": "totally_unknown_kind", "subject": HERO})
    assert r.status_code == 422
    assert "unknown finding kind" in r.json()["detail"][0]["msg"]
    r = client.post("/api/finding", json={"kind": "<img src=x onerror=1>", "subject": HERO})
    assert r.status_code == 422
    assert not any(e.get("kind") == "totally_unknown_kind"
                   for e in client.get("/api/receipts").json())


def test_every_documented_kind_round_trips_over_http(client):
    from sever.console.schemas import KNOWN_FINDING_KINDS

    for kind in KNOWN_FINDING_KINDS:
        # audit3: ace_granted is only valid WITH a real grant; the
        # informational kinds accept the targetless replay shape.
        body = ({"kind": "ace_granted", "subject": HERO, "target": GMSA,
                 "rel": "GENERIC_ALL"} if kind == "ace_granted"
                else {"kind": kind, "subject": HERO})
        r = client.post("/api/finding", json=body)
        assert r.status_code == 200, kind
        assert r.json()["simulated"] is True


def test_ace_granted_without_target_is_422_not_a_phantom_grant(client):
    r = client.post("/api/finding", json={"kind": "ace_granted", "subject": HERO})
    assert r.status_code == 422
    r = client.post("/api/finding", json={"kind": "ace_granted", "subject": HERO,
                                          "target": HERO, "rel": "GENERIC_ALL"})
    assert r.status_code == 422  # self-grant: engine rejects it, so no mutation claim
    before = client.get("/api/state").json()["edges"]
    assert client.get("/api/state").json()["edges"] == before


def test_finding_on_unknown_principal_is_400(client):
    """Pre-fix (live-verified): a breach on a nonexistent objectid was a 200
    phantom no-op narrated as 'this principal is now assumed controlled'."""
    ghost = "S-1-5-21-2697957641-2271029196-387917394-9999"
    r = client.post("/api/finding", json={"kind": "credential_breach", "subject": ghost})
    assert r.status_code == 400
    assert "unknown subject" in r.json()["detail"]
    r = client.post("/api/finding", json={"kind": "ace_granted", "subject": HERO,
                                          "target": ghost, "rel": "GENERIC_ALL"})
    assert r.status_code == 400
    assert "unknown target" in r.json()["detail"]
    assert ghost not in client.get("/api/state").json()["owned"]


def test_breach_that_sticks_reports_applied_true(client):
    """Pre-fix (live-verified): reachability moved 0->1 while the response
    claimed applied:false — a mutation the report refused to admit."""
    r = client.post("/api/finding", json={"kind": "credential_breach", "subject": HERO})
    assert r.status_code == 200
    body = r.json()
    assert body["applied"] is True
    assert body["reachability"] >= 1


def test_zero_removal_cut_claims_only_no_effect(client):
    """Verdict semantics for the 0-removal case: a cut on an edge that does
    not exist claims NOTHING — 0 relationships removed, reachability
    unchanged, verdict 'no_effect' — and the approved no-op still lands on
    the receipts trail."""
    r = client.post("/api/cut", json={"src": HERO, "dst": "S-1-5-21-t-9999",
                                      "rel": "MEMBER_OF", "approved": True,
                                      "approved_by": "audit3"})
    assert r.status_code == 200
    body = r.json()
    assert body["cut"]["relationships_removed"] == 0
    assert body["verdict"] == "no_effect"
    assert body["before"]["reachability"] == body["after"]["reachability"]
    recs = client.get("/api/receipts").json()
    assert any(e.get("step") == "cut"
              and e["receipt"]["verdict"] == "no_effect"
              and e["receipt"]["cut"]["relationships_removed"] == 0
              for e in recs)


def test_cut_gate_null_and_absent_approved_are_422(client):
    for body in (
        {"src": HERO, "dst": HERO, "rel": "MEMBER_OF", "approved": None},
        {"src": HERO, "dst": HERO, "rel": "MEMBER_OF"},
    ):
        r = client.post("/api/cut", json=body)
        assert r.status_code == 422
        assert client.get("/api/state").json()["edges"]  # engine untouched

