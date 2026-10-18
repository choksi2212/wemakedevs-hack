"""Multi-cut PLANS + collateral-aware ranking — the two improvement-fleet
features this branch ships (audit4/improvements).

DB-free section: the fake port pins the ORDER semantics (coverage desc,
benign-usage asc tie-break), the benign-usage measurement contract
(distinct principals, deterministic sample, sample-size cap), the greedy
plan shape (measured projections on an isolated copy, early stop at
collapse, no invented steps, live estate never mutated), the per-step
human gate on execution, and the drift-stop honesty rule.

Engine section: the same semantics on the REAL FalkorDB engine —
GRAPH.COPY scratch isolation, benign receipts on the frozen sample estate
(pool/sampled sizes + the attacker-only edge ranking first), and an exact
two-cut plan on a tiny synthetic estate whose outcome is fully
deterministic (both plan steps cut the ATTACKER-ONLY edges even though the
engine's own canonical route may differ from the fake's — the collateral
tie-break is what pins it, and the engine SIDs are numbered so the shared
jewel-adjacent edges sort FIRST lexicographically: only the tie-break can
produce the asserted order).
"""
from __future__ import annotations

import pytest

from sever.agent.investigator import Investigator
from sever.core.scoring import (
    benign_edge_usage,
    plan_cut_sequence,
    rank_cut_candidates,
)
from tests.conftest import drop_graph, make_live_port, requires_engine, requires_sample
from tests.test_agent import FakeGraphPort

# ------------------------------------------------------------------
# Tiny estates (DB-free). Node ids are chosen so that the LExicographic
# order alone would rank the collateral-heavy edge FIRST — only the benign
# tie-break can flip it. Zoe is the owned principal and sorts LAST.
# ------------------------------------------------------------------
ZOE = "u-zoe"        # owned (hero) — attacker
T1 = "u-tier1"
A1 = "u-a1"
B1 = "u-b1"
C1 = "u-c1"
MID = "u-mid"
U1 = "u-one"
U2 = "u-two"
DA = "g-da"


def _single_route_port() -> FakeGraphPort:
    """One owned->jewel route where the jewel-adjacent edge ALSO carries a
    benign principal's own access (u-tier1 is a member of g-da)."""
    port = FakeGraphPort(jewels=(DA,))
    port._edges = [(T1, "MEMBER_OF", DA), (ZOE, "GENERIC_ALL", T1)]
    port.mark_owned(ZOE)
    return port


def _two_route_port() -> FakeGraphPort:
    """Two parallel owned->jewel routes + a benign principal (u-one) whose
    own access flows through u-mid -> g-da."""
    port = FakeGraphPort(jewels=(DA,))
    port._edges = [
        (ZOE, "GENERIC_ALL", A1),
        (A1, "MEMBER_OF", DA),
        (ZOE, "WRITE_DACL", B1),
        (B1, "MEMBER_OF", DA),
        (U1, "GENERIC_ALL", MID),
        (MID, "MEMBER_OF", DA),
    ]
    port.mark_owned(ZOE)
    return port


def _three_route_port() -> FakeGraphPort:
    """Three parallel owned->jewel routes: the greedy plan needs all three
    steps to collapse, so a drift can land on an EARLY step with later steps
    left to skip — the shape the 2-route estate can never produce (M81)."""
    port = FakeGraphPort(jewels=(DA,))
    port._edges = [
        (ZOE, "GENERIC_ALL", A1),
        (A1, "MEMBER_OF", DA),
        (ZOE, "WRITE_DACL", B1),
        (B1, "MEMBER_OF", DA),
        (ZOE, "OWNS", C1),
        (C1, "MEMBER_OF", DA),
    ]
    port.mark_owned(ZOE)
    return port


# ------------------------------------------------------------------
# Ranking: coverage desc, benign usage asc on ties, honest field semantics
# ------------------------------------------------------------------


def test_benign_tie_break_flips_equal_coverage_ranking():
    freq = {
        (A1, "MEMBER_OF", DA): 5,   # shared edge: benign flow crosses it
        (ZOE, "GENERIC_ALL", A1): 5,  # attacker-only
        (U2, "OWNS", DA): 7,
    }
    benign = {(A1, "MEMBER_OF", DA): 3}
    # without benign data the coverage argmax still wins outright ...
    coverage_only = rank_cut_candidates(freq, limit=3)
    assert coverage_only[0]["src"] == U2 and coverage_only[0]["dst"] == DA
    # ... but the 5/5 coverage TIE falls to the collateral-blind
    # lexicographic order, which ranks the SHARED edge first (u-a1 < u-zoe):
    assert coverage_only[1]["src"] == A1 and coverage_only[1]["dst"] == DA
    assert all(c["benign_usage"] is None for c in coverage_only), \
        "unmeasured benign usage must be None — never a silent 0"
    # with benign data the attacker-only edge wins the tie:
    ranked = rank_cut_candidates(freq, limit=3, benign=benign)
    assert [(c["src"], c["benign_usage"]) for c in ranked] == [
        (U2, 0),        # highest coverage wins outright (7 > 5)
        (ZOE, 0),       # coverage tie, benign 0 — attacker-only edge first
        (A1, 3),        # coverage tie, benign 3 — shared edge demoted
    ]
    # replay-identical
    assert rank_cut_candidates(freq, limit=3, benign=benign) == ranked


def test_propose_receipts_benign_sample_meta():
    inv = Investigator(_single_route_port())
    proposal = inv.propose(limit=5)
    assert len(proposal) == 2
    # the tie flipped: the attacker-only edge outranks the shared one even
    # though lexicographic alone would have picked the shared edge first
    assert proposal[0]["src"] == ZOE and proposal[0]["benign_usage"] == 0
    assert proposal[1]["src"] == T1 and proposal[1]["benign_usage"] == 1
    # every item cites the sample the estimate came from
    assert all(c["benign_sample"] == {"sampled": 1, "pool": 1} for c in proposal)


def test_benign_edge_usage_counts_distinct_principals():
    port = FakeGraphPort(jewels=(DA,))
    port._edges = [
        (U1, "GENERIC_ALL", MID),
        (U2, "GENERIC_ALL", MID),
        (MID, "MEMBER_OF", DA),
        (ZOE, "GENERIC_ALL", MID),
    ]
    port.mark_owned(ZOE)
    meta = benign_edge_usage(port)
    # owned principals are excluded from the benign pool
    assert meta["pool"] == 3 and meta["sampled"] == 3
    # two DIFFERENT benign principals (u-one, u-two) plus u-mid's own path
    # cross the shared edge: 3 principals, counted distinctly — not per-path
    assert meta["usage"][(MID, "MEMBER_OF", DA)] == 3
    assert meta["usage"][(U1, "GENERIC_ALL", MID)] == 1
    assert meta["usage"][(U2, "GENERIC_ALL", MID)] == 1
    # the owned principal's own edge carries no benign flow
    assert (ZOE, "GENERIC_ALL", MID) not in meta["usage"]
    # deterministic: same estate, same numbers, every time
    assert benign_edge_usage(port) == meta


def test_benign_edge_usage_respects_the_sample_cap():
    port = _two_route_port()
    full = benign_edge_usage(port)
    capped = benign_edge_usage(port, sample_size=2)
    assert full["sampled"] == 4 and capped["sampled"] == 2
    # a capped sample can only ever see <= the full sample's usage
    for edge, count in capped["usage"].items():
        assert count <= full["usage"].get(edge, 0)


def test_benign_edge_usage_requires_a_port_that_lists_principals():
    class _NoList(FakeGraphPort):
        user_objectids = None  # type: ignore[assignment]

    with pytest.raises(TypeError, match="user_objectids"):
        benign_edge_usage(_NoList(jewels=(DA,)))


# ------------------------------------------------------------------
# The PLAN: greedy k-cut sequence with measured per-step projections
# ------------------------------------------------------------------


def test_plan_is_a_two_cut_sequence_degrade_then_collapse():
    port = _two_route_port()
    plan = plan_cut_sequence(port, k=3)
    assert plan["method"] == "graph_copy_remeasure"
    assert plan["base"]["reachability"] == 1
    assert len(plan["steps"]) == 2, "k=3 but the plan invents no third step"
    step1, step2 = plan["steps"]
    # step 1 cuts an attacker-only edge (the collateral tie-break) and the
    # measured projection honestly reports the SURVIVING second route
    assert step1["cut"]["src"] == ZOE and step1["benign_usage"] == 0
    assert step1["projected_reachability"] == 1
    assert step1["projected_delta"] == 0
    assert step1["projected_verdict"] == "degraded"
    # step 2 kills the surviving route -> measured zero -> collapsed
    assert step2["cut"]["src"] == ZOE and step2["benign_usage"] == 0
    assert step2["projected_reachability"] == 0
    assert step2["projected_verdict"] == "collapsed"
    assert plan["plan_completes_at_step"] == 2


def test_plan_projects_on_the_copy_and_never_mutates_the_live_estate():
    port = _two_route_port()
    live_edges_before = port.edge_count()
    live_reach_before = port.reachability()
    plan = plan_cut_sequence(port, k=3)
    assert live_reach_before == 1
    # nothing proposed, nothing executed: the live estate is byte-identical
    assert port.edge_count() == live_edges_before
    assert port.reachability() == live_reach_before
    assert len(plan["steps"]) == 2


def test_plan_on_a_collapsed_surface_plans_nothing():
    port = FakeGraphPort(jewels=(DA,))
    port.mark_owned(ZOE)  # owned but no path anywhere — 0 breach paths
    plan = plan_cut_sequence(port, k=3)
    assert plan["steps"] == []
    assert plan["plan_completes_at_step"] is None
    assert "nothing to plan" in plan["note"]


def test_plan_requires_scratch_copy_support():
    class _NoScratch(FakeGraphPort):
        scratch_copy = None  # type: ignore[assignment]

    with pytest.raises(TypeError, match="scratch_copy"):
        plan_cut_sequence(_NoScratch(jewels=(DA,)), k=2)


def test_plan_rejects_k_below_one():
    with pytest.raises(ValueError):
        plan_cut_sequence(_two_route_port(), k=0)


def test_propose_plan_lands_on_the_ledger():
    inv = Investigator(_two_route_port())
    plan = inv.propose_plan(k=3)
    assert plan["steps"] and plan["steps"][0]["step"] == 1
    assert len(inv.case_log) == 1
    entry = inv.case_log[0]
    # cross-agent ledger contract (audit M46): the event KIND lives under
    # "event" and "step" keeps the unique sequential int id — a plan entry
    # may no longer clobber the counter id with a string
    assert entry["event"] == "plan" and entry["step"] == 1
    assert entry["plan"]["method"] == "graph_copy_remeasure"


# ------------------------------------------------------------------
# Executing the plan: per-step gate, per-step re-measure, drift-stop
# ------------------------------------------------------------------


def test_execute_plan_completes_with_measured_receipts():
    port = _two_route_port()
    inv = Investigator(port)
    plan = inv.propose_plan(k=3)
    result = inv.execute_plan(plan, approved_by="on-call-analyst")
    assert result["status"] == "completed"
    assert result["executed_steps"] == 2
    receipts = result["steps"]
    # every step re-measured live and matched its projection (no drift)
    assert [r["plan_drift"] for r in receipts] == [False, False]
    assert receipts[0]["after"]["reachability"] == 1  # degraded, honestly
    assert receipts[1]["after"]["reachability"] == 0  # collapsed, measured
    assert port.reachability() == 0
    # every executed step is on the ledger with its projection + drift flag
    cut_entries = [e for e in inv.case_log if "cut" in e]
    assert len(cut_entries) == 2
    assert cut_entries[0]["cut"]["plan_step"] == 1
    assert cut_entries[0]["cut"]["projected_reachability"] == 1


def test_execute_plan_stops_at_first_drift_and_executes_no_stale_step():
    port = _two_route_port()
    inv = Investigator(port)
    plan = inv.propose_plan(k=3)
    # the estate mutates AFTER the plan: a third route for zoe appears
    assert port.add_edge(ZOE, MID, "OWNS") is True
    result = inv.execute_plan(plan, approved_by="on-call-analyst")
    assert result["status"] == "drift_stopped_at_step"
    assert result["executed_steps"] == 2
    receipts = result["steps"]
    assert receipts[0]["plan_drift"] is False  # step 1 still matched
    assert receipts[1]["plan_drift"] is True   # step 2 measured 1, projected 0
    # the plan is stale, SEVER stops — and the new route openly survives:
    assert port.reachability() == 1
    assert port.reachability() == receipts[1]["after"]["reachability"]


def test_execute_plan_drift_on_an_earlier_step_skips_every_later_step():
    """Audit M81: the 2-route drift cases always drift on the FINAL step, so
    execute_plan's break-on-drift had nothing left to skip and a mutant that
    removed the break entirely still passed both of them. A 3-route plan
    drifts at step 1 (an outside interdiction severed the two routes the
    plan reaches last): the two LATER steps must never execute, and their
    target edges must still be present on the estate."""
    port = _three_route_port()
    inv = Investigator(port)
    plan = inv.propose_plan(k=3)
    assert len(plan["steps"]) == 3, "three routes need three cuts to collapse"
    assert [s["projected_reachability"] for s in plan["steps"]] == [1, 1, 0]
    # the estate mutates AFTER the plan: an outside operator severs the two
    # routes the plan touches last — at their TAIL edges, which the pinned
    # collateral tie-break never proposes (the zoe attacker edges carry
    # benign 0, the shared tail edges carry the members' own benign 1)
    assert port.cut(B1, DA, "MEMBER_OF") == 1
    assert port.cut(C1, DA, "MEMBER_OF") == 1
    result = inv.execute_plan(plan, approved_by="on-call-analyst")
    assert result["status"] == "drift_stopped_at_step"
    # step 1 measured 0 against a projection of 1 -> drift AT STEP 1; the
    # plan stops there and steps 2 + 3 are never executed
    assert result["executed_steps"] == 1 < len(plan["steps"])
    assert result["steps"][0]["plan_drift"] is True
    assert port.reachability() == 0
    assert port.reachability() == result["steps"][0]["after"]["reachability"]
    # the SKIPPED steps' target edges are still on the estate — the stale
    # projections were never cut
    later_cuts = [
        (s["cut"]["src"], s["cut"]["rel"], s["cut"]["dst"])
        for s in plan["steps"][1:]
    ]
    assert later_cuts and all(edge in port._edges for edge in later_cuts), (
        f"a step after the drift executed anyway: {later_cuts}"
    )


def test_execute_plan_gate_refusal_mutates_nothing():
    port = _two_route_port()
    inv = Investigator(port)
    plan = inv.propose_plan(k=3)
    result = inv.execute_plan(plan, gate=lambda step: False)
    assert result["status"] == "gate_refused_at_step"
    assert result["executed_steps"] == 0
    assert port.edge_count() == 6 and port.reachability() == 1
    # cross-agent ledger contract (audit M46): the refusal is the "event"
    # kind; "step" stays the sequential int id, never a clobbering string
    refused = [e for e in inv.case_log if e.get("event") == "plan_gate_refused"]
    assert len(refused) == 1 and isinstance(refused[0]["step"], int)


def test_execute_plan_partial_gate_refusal_stops_before_the_next_step():
    port = _two_route_port()
    inv = Investigator(port)
    plan = inv.propose_plan(k=3)
    approved = {"n": 0}

    def gate(step):
        approved["n"] += 1
        return step["step"] == 1  # approve step 1, refuse everything after

    result = inv.execute_plan(plan, gate=gate)
    assert result["status"] == "gate_refused_at_step"
    assert result["executed_steps"] == 1
    assert approved["n"] == 2, "the gate is consulted per step"
    assert port.reachability() == 1  # one route survives untouched


def test_execute_plan_requires_explicit_approval():
    inv = Investigator(_two_route_port())
    plan = inv.propose_plan(k=3)
    with pytest.raises(ValueError, match="explicit"):
        inv.execute_plan(plan, require_explicit_approval="yes")


# ------------------------------------------------------------------
# Engine pins: the same semantics on the REAL FalkorDB engine
# ------------------------------------------------------------------

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"

# tiny synthetic estate on the engine: exactly the two-route shape above,
# with the crown jewel detected by RID (Group ending -512) like real data.
# SIDs are numbered so the shared jewel-adjacent MEMBER_OF edges
# (S_A1/S_B1 -> S_DA, benign usage 1) sort FIRST lexicographically and the
# attacker's own edges sort LAST (audit M83): with zoe at -1001 the old
# numbering made the asserted cuts indistinguishable from the plain
# lexicographic fallback — now ONLY the collateral tie-break can produce
# them, which is the property the engine pin claims to test.
S_A1 = "S-1-5-21-t-777-1001"
S_B1 = "S-1-5-21-t-777-1002"
S_MID = "S-1-5-21-t-777-1003"
S_U1 = "S-1-5-21-t-777-1004"
S_ZOE = "S-1-5-21-t-777-1005"
S_DA = "S-1-5-21-t-777-512"


def _synth_two_route_port(graph_name: str):
    from sever.etl.ad_collectors import NormalizedGraph

    port = make_live_port(graph_name, load_sample=False)
    drop_graph(port, graph_name)
    g = NormalizedGraph()
    for oid, name in ((S_ZOE, "zoe"), (S_A1, "a1"), (S_B1, "b1"),
                      (S_MID, "mid"), (S_U1, "one")):
        g.add_node(oid, "User", {"name": name})
    g.add_node(S_DA, "Group", {"name": "Domain Admins"})
    for src, rel, dst in (
        (S_ZOE, "GENERIC_ALL", S_A1),
        (S_A1, "MEMBER_OF", S_DA),
        (S_ZOE, "WRITE_DACL", S_B1),
        (S_B1, "MEMBER_OF", S_DA),
        (S_U1, "GENERIC_ALL", S_MID),
        (S_MID, "MEMBER_OF", S_DA),
    ):
        g.add_edge(src, dst, rel)
    port.load(g)
    port.mark_owned(S_ZOE)
    return port


class TestLivePlanningEngine:
    """GRAPH.COPY projections, benign receipts and plan execution on the
    real engine (docker compose up -d, or SEVER_FALKOR_HOST=...). Each test
    self-contains its graph and deletes it (SEVER_TEST_GRAPH_PREFIX
    namespaces every key on a shared engine)."""

    def _key_exists(self, port, key: str) -> int:
        return int(port.graph.client.execute_command("EXISTS", key))

    @requires_engine
    def test_scratch_copy_is_isolated_and_droppable(self):
        port = _synth_two_route_port("sever_test_planning_copy")
        try:
            scratch_name = f"{port.graph_name}_copyprobe"
            scratch = port.scratch_copy(scratch_name)
            assert scratch.node_count() == port.node_count()
            assert scratch.edge_count() == port.edge_count() == 6
            # a mutation on the copy never reaches the live estate:
            assert scratch.cut(S_ZOE, S_A1, "GENERIC_ALL") == 1
            assert scratch.edge_count() == 5
            assert port.edge_count() == 6
            scratch.drop()
            assert self._key_exists(port, scratch_name) == 0, \
                "drop() must really delete the engine key"
        finally:
            drop_graph(port, "sever_test_planning_copy")

    @requires_engine
    @requires_sample
    def test_benign_usage_receipts_on_the_sample_estate(self):
        port = make_live_port("sever_test_planning_benign")
        try:
            port.mark_owned(HERO)
            assert port.user_objectids(), "sample estate lists its users"
            proposal = Investigator(port).propose(limit=5)
            top_coverage = proposal[0]["paths_on"]
            assert top_coverage >= 1
            # the sample's 99 users minus the owned hero
            assert proposal[0]["benign_sample"]["pool"] == len(port.user_objectids()) - 1
            assert proposal[0]["benign_sample"]["sampled"] == 25, \
                "the documented BENIGN_SAMPLE_SIZE cap"
            # property the ranking promises: within equal coverage, benign
            # usage is non-decreasing down the list
            for higher, lower in zip(proposal, proposal[1:]):
                if higher["paths_on"] == lower["paths_on"]:
                    assert higher["benign_usage"] <= lower["benign_usage"]
            # the frozen sample's coverage-tie set contains both
            # attacker-only edges AND a shared one — and the #1 cut is
            # attacker-only (the collateral tie-break decides the demo):
            tie_edges = [c for c in proposal if c["paths_on"] == top_coverage]
            assert any(c["benign_usage"] >= 1 for c in tie_edges), \
                "the sample has a shared jewel-adjacent edge among the ties"
            assert proposal[0]["benign_usage"] == 0, \
                "the #1 proposal is an attacker-only edge"
        finally:
            drop_graph(port, "sever_test_planning_benign")

    @requires_engine
    @requires_sample
    def test_plan_on_sample_estate_projects_without_mutating_live(self):
        port = make_live_port("sever_test_planning_sample")
        try:
            port.mark_owned(HERO)
            live_reach = port.reachability()
            live_edges = port.edge_count()
            plan = Investigator(port).propose_plan(k=3)
            assert plan["method"] == "graph_copy_remeasure"
            assert plan["steps"], "the sample estate with the hero owned plans >= 1 cut"
            projections = [s["projected_reachability"] for s in plan["steps"]]
            assert projections == sorted(projections, reverse=True), \
                "projections are monotone non-increasing down the plan"
            for step in plan["steps"]:
                assert isinstance(step["benign_usage"], int)
                assert step["projected_verdict"] in ("degraded", "collapsed")
                assert step["projected_verdict"] != "collapsed" or \
                    step["projected_reachability"] == 0
            # the live estate is untouched by the projection work:
            assert port.reachability() == live_reach
            assert port.edge_count() == live_edges
            # and no plan-scratch copy leaked on the engine: scoring names
            # every scratch {graph}_plan_scratch_<8-hex> (random per plan),
            # so probe the NAMESPACE, never a single key (audit M82: the old
            # check asserted the absence of a key scoring.py cannot create
            # and could not fail on a real leak)
            leaked = port.graph.client.execute_command(
                "KEYS", f"{port.graph_name}_plan_scratch_*")
            assert not leaked, (
                f"plan scratch keys leaked on the engine: {leaked} — "
                "plan_cut_sequence's finally drop() must remove every copy"
            )
        finally:
            drop_graph(port, "sever_test_planning_sample")

    @requires_engine
    def test_two_cut_plan_and_execution_on_the_engine(self):
        port = _synth_two_route_port("sever_test_planning_synth")
        try:
            assert port.reachability() == 1
            inv = Investigator(port)
            plan = inv.propose_plan(k=3)
            assert len(plan["steps"]) == 2
            # BOTH steps cut the attacker's own edges (benign 0): the
            # collateral tie-break on the engine prefers them over the
            # shared jewel-adjacent MEMBER_OF edges (benign 1) — whichever
            # route the engine's shortestPath picked as canonical. The SIDs
            # sort the SHARED edges first, so the lexicographic fallback
            # alone would cut S_A1/S_B1's membership edges instead: only
            # the benign tie-break can pass this pin (audit M83).
            for step in plan["steps"]:
                assert step["cut"]["src"] == S_ZOE
                assert step["benign_usage"] == 0
            assert plan["steps"][0]["projected_verdict"] == "degraded"
            assert plan["steps"][1]["projected_verdict"] == "collapsed"
            assert plan["plan_completes_at_step"] == 2
            # execute: every step re-measured live, zero drift, full collapse
            result = inv.execute_plan(plan, approved_by="on-call-analyst")
            assert result["status"] == "completed"
            assert result["executed_steps"] == 2
            assert port.reachability() == 0
            # re-plan on the collapsed surface: honestly nothing to plan
            replan = inv.propose_plan(k=3)
            assert replan["steps"] == []
            assert "nothing to plan" in replan["note"]
        finally:
            drop_graph(port, "sever_test_planning_synth")

    @requires_engine
    def test_engine_plan_stops_at_drift(self):
        port = _synth_two_route_port("sever_test_planning_drift")
        try:
            inv = Investigator(port)
            plan = inv.propose_plan(k=3)
            # the estate mutates AFTER the plan — a third route appears:
            assert port.add_edge(S_ZOE, S_MID, "OWNS") is True
            result = inv.execute_plan(plan, approved_by="on-call-analyst")
            assert result["status"] == "drift_stopped_at_step"
            assert result["steps"][-1]["plan_drift"] is True
            # the new route openly survives — never a silent stale success
            assert port.reachability() == 1
        finally:
            drop_graph(port, "sever_test_planning_drift")
