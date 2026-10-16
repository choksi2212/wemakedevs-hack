"""audit7/perf-api — equivalence proofs and engine-call receipts for the
console fold layer (sever/console/app.py ONLY).

Every fold must be INVISIBLE at the contract level: the folded fast path and
the original port-method slow path must answer byte-identically, and the
response shapes must keep every existing field. This suite pins:

1. PROBE EQUIVALENCE — the one-round-trip estate probe equals
   node_count()/edge_count()/owned_ids()/crown_jewels(), before and after a
   mutation (the probe IS the estate generation the /api/state cache keys
   on, so this equivalence is what makes caching semantically safe).
2. RESPONSE EQUIVALENCE — /api/state, /api/paths and /api/proposal answer
   identically with the fold enabled and with it refused (probe forced to
   None = the exact original code path; same estate, same app instance).
3. PLAN EQUIVALENCE — GET /api/plan (the folded greedy copy+measure loop)
   equals scoring.plan_cut_sequence run directly on the same live estate:
   same steps, same cuts, same measured projections, same receipt fields.
4. ENGINE-CALL RECEIPTS — the exact round-trip counts per endpoint,
   counted at the redis client so the /api/plan scratch copy is included.
   Name lookups are display-only and cached app-lifetime, so endpoints are
   measured WARM (after one uncounted call resolved every name): /api/state
   11 -> 1 warm / 3 after a mutation; /api/paths 17 -> 3; /api/proposal
   185 -> 6; /api/plan 398 -> ~21 (2 steps on the frozen sample). The
   baseline numbers were measured on this same fixture before the fold
   landed (receipt in the branch report).
5. ZERO STALE ANSWERS — the cache discipline: a console cut, an
   out-of-band cut by a second port, and an out-of-band mark_owned each
   change what the next /api/state answers; a drifted query constant makes
   the fold refuse itself (fallback, never a wrong answer); an engine
   outage mid-fast-path is still the clean 503 lane with its ledger line.
"""
from __future__ import annotations

import json

import pytest

from sever.core.jewels import DEFAULT_HOP_CAP
from tests.conftest import (
    drop_graph,
    prefixed,
    requires_engine,
    requires_sample,
)

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"
GMSA = "S-1-5-21-2697957641-2271029196-387917394-2102"
GRAPH = prefixed("sever_audit7_api_folds")

pytestmark = [requires_engine, requires_sample]


class CountingClient:
    """Every execute_command is one engine round-trip — the /api/plan scratch
    graphs reuse this client, so their queries are counted too."""

    def __init__(self, inner):
        self._inner = inner
        self.calls = 0

    def execute_command(self, *args, **kwargs):
        self.calls += 1
        return self._inner.execute_command(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._inner, name)


@pytest.fixture()
def rig(tmp_path, monkeypatch):
    """One console on a fresh sample estate with HERO owned, a counting
    client, and an isolated receipts ledger directory."""
    monkeypatch.chdir(tmp_path)  # CaseLog root lands in the tmp dir
    monkeypatch.setenv("SEVER_CONSOLE_NO_BOOTSTRAP", "1")
    monkeypatch.setenv("SEVER_FALKOR_GRAPH", GRAPH)

    from sever.core.falkor_port import FalkorGraphPort
    from sever.etl.ad_collectors import parse_ad_dir
    from tests.conftest import SAMPLE_DIR

    port = FalkorGraphPort(graph_name=GRAPH)
    drop_graph(port, GRAPH)
    port.load(parse_ad_dir(SAMPLE_DIR))
    port.mark_owned(HERO)
    cc = CountingClient(port.graph.client)
    port.graph.client = cc
    port.graph.execute_command = cc.execute_command

    import sever.console.app as appmod

    app = appmod.build_app(port=port)
    from fastapi.testclient import TestClient

    tc = TestClient(app)
    yield {"tc": tc, "port": port, "cc": cc, "appmod": appmod}
    drop_graph(port, GRAPH)


def _breach(tc) -> None:
    r = tc.post("/api/finding", json={"kind": "credential_breach", "subject": HERO})
    assert r.status_code == 200, r.text


def _force_slow(rig, monkeypatch):
    """Refuse the fold: every handler then answers through the EXACT original
    port-method path (the same code the engine-free fake ports exercise)."""
    monkeypatch.setattr(rig["appmod"], "_estate_probe", lambda port: None)


# ---------------------------------------------------------------------------
# 1. probe equivalence — the cache's generation check is the port's own truth
# ---------------------------------------------------------------------------

def test_probe_equals_port_methods_before_and_after_mutation(rig):
    appmod = rig["appmod"]
    port = rig["port"]

    def check():
        probe = appmod._estate_probe(port)
        assert probe is not None, "the live engine must speak the folded dialect"
        nodes, edges, owned, jewels = probe
        assert (nodes, edges, owned, jewels) == (
            port.node_count(), port.edge_count(),
            port.owned_ids(), port.crown_jewels(),
        )

    check()
    _breach(rig["tc"])
    check()


# ---------------------------------------------------------------------------
# 2. response equivalence — fold on vs fold refused, same estate, same app
# ---------------------------------------------------------------------------

def test_state_folded_response_equals_original(rig, monkeypatch):
    tc = rig["tc"]
    fast = tc.get("/api/state").json()
    _force_slow(rig, monkeypatch)
    slow = tc.get("/api/state").json()
    assert fast == slow, "the folded /api/state must answer byte-identically"
    # every pre-fold field is still present for the UI (add-only contract)
    for field in ("backend", "graph", "nodes", "edges", "jewels", "owned",
                  "owned_names", "reachability"):
        assert field in fast


def test_paths_folded_response_equals_original(rig, monkeypatch):
    tc = rig["tc"]
    _breach(tc)
    fast = tc.get("/api/paths").json()
    _force_slow(rig, monkeypatch)
    slow = tc.get("/api/paths").json()
    assert fast == slow, "the folded /api/paths must answer byte-identically"
    assert fast["paths"], "the armed estate has paths to enumerate"


def test_proposal_folded_response_equals_original(rig, monkeypatch):
    tc = rig["tc"]
    _breach(tc)
    fast = tc.get("/api/proposal").json()
    _force_slow(rig, monkeypatch)
    slow = tc.get("/api/proposal").json()
    assert fast == slow, "the folded /api/proposal must answer byte-identically"
    assert fast and {"src", "rel", "dst", "paths_on", "benign_usage",
                     "benign_sample", "src_name", "dst_name"} <= set(fast[0])


# ---------------------------------------------------------------------------
# 3. plan equivalence — the fold IS the original algorithm, measured
# ---------------------------------------------------------------------------

def test_plan_fold_equals_scoring_plan_cut_sequence(rig):
    """GET /api/plan answers exactly what running the ORIGINAL greedy
    copy+measure loop (scoring.plan_cut_sequence) on the same live estate
    answers — steps, cuts, measured projections and receipt fields."""
    from sever.core.scoring import plan_cut_sequence

    tc, port = rig["tc"], rig["port"]
    _breach(tc)
    r = tc.get("/api/plan")
    assert r.status_code == 200, r.text[:300]
    folded = r.json()
    original = plan_cut_sequence(port, k=3, hop_cap=DEFAULT_HOP_CAP)
    assert folded == original, (
        "the folded plan must equal scoring.plan_cut_sequence field-for-field:\n"
        + json.dumps({"folded": folded, "original": original}, indent=1)[:4000]
    )


# ---------------------------------------------------------------------------
# 4. engine-call receipts — the exact round-trip counts per endpoint
# ---------------------------------------------------------------------------

def test_round_trip_receipts(rig):
    tc, cc = rig["tc"], rig["cc"]

    # cold poll: probe + two arms + one name lookup (HERO is the only owned)
    cc.calls = 0
    assert tc.get("/api/state").status_code == 200
    assert cc.calls == 4, f"cold /api/state: expected 4 (3 + name), got {cc.calls}"
    # warm polls: the probe IS the cache check — one round-trip, zero stale
    for _ in range(2):
        cc.calls = 0
        assert tc.get("/api/state").status_code == 200
        assert cc.calls == 1, f"warm /api/state must be 1 round-trip, got {cc.calls}"

    # after a console mutation the poll recomputes (probe + two arms)
    r = tc.post("/api/cut", json={"src": HERO, "dst": GMSA, "rel": "GENERIC_ALL",
                                  "approved": True, "approved_by": "audit7"})
    assert r.status_code == 200
    cc.calls = 0
    assert tc.get("/api/state").status_code == 200
    assert cc.calls == 3, f"post-mutation /api/state: expected 3, got {cc.calls}"

    # re-arm the estate for the remaining endpoints
    _breach(tc)
    r = tc.post("/api/finding", json={"kind": "ace_granted", "subject": HERO,
                                      "target": GMSA, "rel": "GENERIC_ALL"})
    assert r.status_code == 200

    # /api/paths: one uncounted call resolves every display name (app-lifetime
    # cache), then the counted call is exactly probe + two arms
    assert tc.get("/api/paths").json()["paths"]
    cc.calls = 0
    assert tc.get("/api/paths").json()["paths"]
    assert cc.calls == 3, f"/api/paths: expected 3 (probe + 2 arms), got {cc.calls}"

    # /api/proposal: probe + user pool + two benign arms + two freq arms
    assert tc.get("/api/proposal").json()
    cc.calls = 0
    assert tc.get("/api/proposal").json()
    assert cc.calls == 6, (
        f"/api/proposal: expected 6 (probe + pool + 2 benign arms + 2 freq arms), "
        f"got {cc.calls}"
    )

    # /api/plan: 398 before the fold. After: base probe+arms (3), scratch
    # delete+copy (2), user pool (1), 7 per step (2 freq arms + 2 benign arms
    # + 1 cut + 2 reach arms), drop (1) — 21 measured on the frozen sample
    # (collapses at step 2); bound at 30 so a full 3-step plan still fits.
    cc.calls = 0
    plan = tc.get("/api/plan").json()
    assert plan["steps"], "the armed estate must have steps to plan"
    assert cc.calls <= 30, f"/api/plan round-trips must be <=30, got {cc.calls}"


# ---------------------------------------------------------------------------
# 5. zero stale answers — the caching discipline, receipted
# ---------------------------------------------------------------------------

def test_console_cut_invalidates_state_cache(rig):
    tc = rig["tc"]
    _breach(tc)
    assert tc.get("/api/state").json()["reachability"] == 1
    prop = tc.get("/api/proposal").json()
    top = prop[0]
    r = tc.post("/api/cut", json={"src": top["src"], "dst": top["dst"],
                                  "rel": top["rel"], "approved": True,
                                  "approved_by": "audit7"})
    assert r.status_code == 200
    state = tc.get("/api/state").json()
    assert state["reachability"] == 0, "a console cut must never serve stale reachability"


def test_out_of_band_cut_invalidates_state_cache(rig):
    """A mutation by ANOTHER client (a second port on the same engine key)
    has no generation counter — the probe's estate signature must catch it."""
    from sever.core.falkor_port import FalkorGraphPort

    tc = rig["tc"]
    _breach(tc)
    assert tc.get("/api/state").json()["reachability"] == 1
    other = FalkorGraphPort(graph_name=GRAPH)
    prop = tc.get("/api/proposal").json()
    top = prop[0]
    removed = other.cut(top["src"], top["dst"], top["rel"])
    assert removed == 1, "the out-of-band cut must actually cut something"
    state = tc.get("/api/state").json()
    assert state["reachability"] == 0, "an out-of-band cut must never serve stale"


def test_out_of_band_mark_owned_invalidates_state_cache(rig):
    from sever.core.falkor_port import FalkorGraphPort

    tc = rig["tc"]
    other = FalkorGraphPort(graph_name=GRAPH)
    before = tc.get("/api/state").json()
    assert GMSA not in before["owned"]
    other.mark_owned(GMSA)  # a real principal of the loaded estate
    after = tc.get("/api/state").json()
    assert GMSA in after["owned"], "an out-of-band mark_owned must never serve stale"
    assert len(after["owned_names"]) == len(after["owned"]), \
        "the refreshed owned list must carry its display names too"


def test_drifted_constant_refuses_the_fold_not_the_answer(rig, monkeypatch):
    """If the port's query constants drift from what the fold expects, the
    fold must REFUSE ITSELF (fallback to the original path), never answer
    from a mis-built query."""
    appmod, tc = rig["appmod"], rig["tc"]
    fast = tc.get("/api/state").json()
    with monkeypatch.context() as m:
        m.setattr(appmod, "JEWELS_QUERY", "MATCH (g:Group) WHERE g.objectid ENDS WITH '-512'")
        m.setattr(appmod, "_fold_cache", {})
        slow = tc.get("/api/state").json()
    assert slow == fast, "the refused fold must answer identically through the port methods"
    # the fold is rebuilt from the REAL constants afterwards and works again
    assert appmod._estate_probe(rig["port"]) is not None


def test_engine_outage_on_fast_path_is_still_the_clean_503_lane(rig):
    """A dead engine inside the folded path (probe or arms) surfaces as the
    machine-readable 503 — same lane as the port methods, never a 500."""
    import redis

    tc = rig["tc"]
    port = rig["port"]
    real_graph = port.graph

    class _DeadGraph:
        client = real_graph.client

        def query(self, *a, **kw):
            raise redis.exceptions.ConnectionError(
                "Error 10061 connecting to 127.0.0.1:6379. Connection refused.")

    port.graph = _DeadGraph()
    try:
        r = tc.get("/api/state")
        assert r.status_code == 503
        assert r.json()["detail"].startswith("engine unreachable")
        r = tc.get("/api/plan")
        assert r.status_code == 503
        assert r.json()["detail"].startswith("engine unreachable")
        recs = tc.get("/api/receipts").json()
        assert any(e.get("step") == "plan_failed"
                   and e.get("outcome") == "unknown" for e in recs), \
            "the outage attempt must be on the receipts trail"
    finally:
        port.graph = real_graph
