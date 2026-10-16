"""audit7/perf-scoring — equivalence + perf pins for the incremental plan.

WHAT CHANGED (sever/core/scoring.py + sever/core/port.py ONLY):
1. plan_cut_sequence measures its base AND every per-step projection with the
   per-(owned, jewel) canonical enumeration it already runs for edge scoring
   (_reached_principals), replacing the two-arm all-pairs reachability query
   — the 2-4s-per-traversal query on the multi-tenant cloud engine that made
   a k=3 plan take 13-14s in production. Every step still re-enumerates the
   MUTATED copy after its cut: re-routes stay visible, nothing is frozen.
2. benign_edge_usage enumerates the whole sampled pool through ONE
   canonical_paths_multi call — a GraphPort seam whose DEFAULT is the
   identical per-principal paths_to_jewels loop, and which a backend can
   override with a single UNWIND query (BatchedFalkorPort below is the
   engine-verified override the falkor backend can adopt verbatim).

EQUIVALENCE METHOD: ``old_plan`` is a faithful replica of the pre-audit7
algorithm (live snapshot() base + per-step scratch.edge_frequency() +
scratch.reachability()). Every test in this file asserts old == new
receipts — DB-free on FakeGraphPort estates, and on the REAL engine: the
sample estate, the deterministic two-route synth estate, deterministic fuzz
micro-graphs, and the owned-jewel (0-hop breach) case where the union term
is load-bearing. The only intentional divergence: on a FakeGraphPort estate
whose OWNED principal IS a jewel, the fake's own reachability() omits the
0-hop breach that the engine (and the new plan) counts — pinned explicitly
in test_owned_is_jewel_fake_divergence_is_engine_semantics.

PERF PINS: the counting tests pin ZERO two-arm queries in the new plan and a
deterministic round-trip ceiling; the receipt test measures old vs new vs
batched wall times and writes docs/receipts-style JSON to
SEVER_PERF_RECEIPT_DIR when that env var is set.
"""
from __future__ import annotations

import json
import os
import random
import statistics
import time
from pathlib import Path
from typing import Any

import pytest

from sever.core.falkor_port import (
    REACHABILITY_ARM_TEMPLATES,
    FalkorGraphPort,
    _row_to_hops,
)
from sever.core.jewels import DEFAULT_HOP_CAP, TRAVERSAL_RELS_SET, cypher_traversal_pattern
from sever.core.port import GraphPort
from sever.core.scoring import (
    BENIGN_SAMPLE_SIZE,
    benign_edge_usage,
    interdict,
    plan_cut_sequence,
    rank_cut_candidates,
    snapshot,
)
from sever.etl.ad_collectors import NormalizedGraph
from tests.conftest import (
    drop_graph,
    make_live_port,
    prefixed,
    requires_engine,
    requires_sample,
)
from tests.interdiction_fuzz import random_micro_graph
from tests.test_agent import FakeGraphPort

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"


# ---------------------------------------------------------------------------
# The OLD algorithm, frozen verbatim (pre-audit7 plan_cut_sequence) — the
# reference every new receipt is compared against. It uses the CURRENT
# benign_edge_usage/rank_cut_candidates (unchanged semantics: the ABC seam
# default IS the old per-principal loop) and the unchanged snapshot().
# ---------------------------------------------------------------------------

def old_plan(
    port: GraphPort,
    k: int = 3,
    hop_cap: int = DEFAULT_HOP_CAP,
    benign_sample_size: int = BENIGN_SAMPLE_SIZE,
    scratch_name: str | None = None,
) -> dict[str, Any]:
    if k < 1:
        raise ValueError("k must be >= 1")
    copier = getattr(port, "scratch_copy", None)
    if copier is None:
        raise TypeError("plan_cut_sequence requires a port with scratch_copy(name)")
    base = snapshot(port, hop_cap)
    if base["reachability"] == 0:
        return {
            "k": k,
            "method": "graph_copy_remeasure",
            "base": {"reachability": 0, "owned": base["owned"], "jewels": base["jewels"]},
            "benign_sample_size": benign_sample_size,
            "steps": [],
            "plan_completes_at_step": None,
            "note": "surface already collapsed (0 breach paths) — nothing to plan",
        }
    import os as _os

    name = scratch_name or (
        f"{getattr(port, 'graph_name', 'graph')}_plan_scratch_{_os.urandom(4).hex()}"
    )
    scratch = copier(name)
    steps: list[dict[str, Any]] = []
    completes_at: int | None = None
    try:
        prev = base["reachability"]
        for i in range(1, k + 1):
            freq = scratch.edge_frequency(hop_cap)
            if not freq:
                break
            benign = benign_edge_usage(scratch, hop_cap, benign_sample_size)
            top = rank_cut_candidates(freq, limit=1, benign=benign["usage"])[0]
            removed = scratch.cut(top["src"], top["dst"], top["rel"])
            projected = scratch.reachability(hop_cap)
            if removed == 0:
                verdict = "no_effect"
            elif projected == 0:
                verdict = "collapsed"
            else:
                verdict = "degraded"
            steps.append({
                "step": i,
                "cut": {"src": top["src"], "rel": top["rel"], "dst": top["dst"]},
                "paths_on": top["paths_on"],
                "benign_usage": top["benign_usage"],
                "projected_reachability": projected,
                "projected_delta": projected - prev,
                "projected_verdict": verdict,
            })
            prev = projected
            if projected == 0:
                completes_at = i
                break
    finally:
        scratch.drop()
    return {
        "k": k,
        "method": "graph_copy_remeasure",
        "base": {"reachability": base["reachability"], "owned": base["owned"], "jewels": base["jewels"]},
        "benign_sample_size": benign_sample_size,
        "steps": steps,
        "plan_completes_at_step": completes_at,
        "honesty": (
            "projections are measured on an isolated GRAPH.COPY of the live "
            "estate after each cut; execution re-measures reality per step "
            "and stops at the first drift — a projected number is never the "
            "claim, the live receipt is"
        ),
    }


# ---------------------------------------------------------------------------
# DB-free estates
# ---------------------------------------------------------------------------

ZOE = "u-zoe"
T1 = "u-tier1"
A1 = "u-a1"
B1 = "u-b1"
MID = "u-mid"
U1 = "u-one"
U2 = "u-two"
DA = "g-da"


def _port(edges, jewels=(DA,), owned=(ZOE,)):
    port = FakeGraphPort(jewels=jewels)
    port._edges = list(edges)
    for o in owned:
        port.mark_owned(o)
    return port


def estate_single_route():
    return _port([(T1, "MEMBER_OF", DA), (ZOE, "GENERIC_ALL", T1)])


def estate_two_route():
    return _port([
        (ZOE, "GENERIC_ALL", A1), (A1, "MEMBER_OF", DA),
        (ZOE, "WRITE_DACL", B1), (B1, "MEMBER_OF", DA),
        (U1, "GENERIC_ALL", MID), (MID, "MEMBER_OF", DA),
    ])


def estate_three_route():
    return _port([
        (ZOE, "GENERIC_ALL", A1), (A1, "MEMBER_OF", DA),
        (ZOE, "WRITE_DACL", B1), (B1, "MEMBER_OF", DA),
        (ZOE, "OWNS", MID), (MID, "MEMBER_OF", DA),
        (U1, "GENERIC_ALL", MID), (U2, "GENERIC_ALL", MID),
    ])


def estate_multi_owned():
    return _port([
        (ZOE, "GENERIC_ALL", A1), (A1, "MEMBER_OF", DA),
        (A1, "WRITE_DACL", B1), (B1, "MEMBER_OF", DA),
        (U1, "GENERIC_ALL", MID), (MID, "MEMBER_OF", DA),
    ], owned=(ZOE, A1))


def estate_shared_tie():
    # zoe's two routes have EQUAL coverage; the a1 route is shared with a
    # benign principal's flow so the collateral tie-break must pick zoe's
    # attacker-only edge first, then re-measure the survivor — old and new
    # must agree on the flip at every step.
    return _port([
        (ZOE, "GENERIC_ALL", A1), (A1, "MEMBER_OF", DA),
        (ZOE, "FORCE_CHANGE_PASSWORD", B1), (B1, "MEMBER_OF", DA),
        (U1, "ADD_MEMBER", A1),
    ])


def estate_parallel_edges():
    # the SAME (src, rel, dst) triple present twice: the canonical path uses
    # the triple once, the cut removes BOTH copies and counts 2
    return _port([
        (ZOE, "GENERIC_ALL", A1), (A1, "MEMBER_OF", DA),
        (ZOE, "GENERIC_ALL", A1),
    ])


def estate_collapsed():
    return _port([])


def estate_long_chain():
    # a 5-hop chain: hop_cap 2 truncates it (unreachable), 12 traverses it —
    # the cap binds in BOTH the old and the new measurement form
    chain = [("u-c0", "GENERIC_ALL", "u-c1"), ("u-c1", "GENERIC_ALL", "u-c2"),
             ("u-c2", "GENERIC_ALL", "u-c3"), ("u-c3", "GENERIC_ALL", DA)]
    return _port([("ZOE_PLACEHOLDER", "GENERIC_ALL", "u-c0")] + chain,
                 owned=("ZOE_PLACEHOLDER",))


FAKE_ESTATES = {
    "single_route": estate_single_route,
    "two_route": estate_two_route,
    "three_route": estate_three_route,
    "multi_owned": estate_multi_owned,
    "shared_tie": estate_shared_tie,
    "parallel_edges": estate_parallel_edges,
    "collapsed": estate_collapsed,
    "long_chain": estate_long_chain,
}


# ---------------------------------------------------------------------------
# DB-free equivalence: old vs new receipts on every estate, k and cap sweep
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("estate_name", sorted(FAKE_ESTATES))
@pytest.mark.parametrize("k", [1, 2, 3, 4])
def test_old_vs_new_plan_receipts_match_on_fake_estates(estate_name, k):
    port = FAKE_ESTATES[estate_name]()
    assert plan_cut_sequence(port, k=k) == old_plan(port, k=k), estate_name


@pytest.mark.parametrize("estate_name", ["single_route", "two_route", "three_route", "multi_owned", "long_chain"])
@pytest.mark.parametrize("cap", [1, 2, 3, 12])
def test_old_vs_new_plan_receipts_match_across_hop_caps(estate_name, cap):
    port = FAKE_ESTATES[estate_name]()
    assert plan_cut_sequence(port, k=3, hop_cap=cap) == old_plan(port, k=3, hop_cap=cap)


def test_old_vs_new_plan_honor_explicit_scratch_name():
    port = estate_two_route()
    assert plan_cut_sequence(port, k=2, scratch_name="pe_explicit") == \
        old_plan(port, k=2, scratch_name="pe_explicit")


def test_benign_usage_matches_the_per_principal_reference():
    for estate_name, make in FAKE_ESTATES.items():
        port = make()
        meta = benign_edge_usage(port)
        # reference: the pre-audit7 inline loop, computed by hand
        owned = set(port.owned_ids())
        pool = sorted(set(port.user_objectids()) - owned)
        step = max(1, len(pool) // BENIGN_SAMPLE_SIZE) if pool else 1
        sample = pool[::step][:BENIGN_SAMPLE_SIZE] if pool else []
        ref: dict[tuple[str, str, str], int] = {}
        for principal in sample:
            hops = {tuple(h) for p in port.paths_to_jewels(principal) for h in p}
            for h in hops:
                ref[h] = ref.get(h, 0) + 1
        assert meta["usage"] == ref, estate_name
        assert meta["sampled"] == len(sample) and meta["pool"] == len(pool)


def test_owned_is_jewel_fake_divergence_is_engine_semantics():
    """The ONE old-vs-new divergence — and it is the FAKE that is lossy, not
    the new plan. FakeGraphPort.reachability() omits the owned-jewel 0-hop
    breach (its BFS returns an empty hop list for a self-pair), while the
    engine's reachability() counts it (pinned live in
    tests/test_live_interdiction_invariants.py, whose per-pair reference
    includes the union) and the ABC contract reads "a path to any crown
    jewel". The new plan counts the 0-hop breach on every backend; the
    engine old-vs-new EQUALITY is pinned live in
    TestPlanEquivalenceEngine::test_old_vs_new_plan_on_owned_jewel_estate —
    on the real backend both forms include the union and agree exactly.
    No pre-existing test plans an owned-is-jewel estate, so this is a new,
    engine-aligned pin of the intentional difference."""
    # (a) the jewel is the ONLY owned principal: old early-returns "nothing
    # to plan" (the fake cannot see the 0-hop breach); new counts it
    port = _port([(T1, "MEMBER_OF", DA)], jewels=(DA,), owned=(DA,))
    old = old_plan(port, k=2)
    new = plan_cut_sequence(port, k=2)
    assert old["base"]["reachability"] == 0 and old["steps"] == []
    assert "note" in old, "old early-returns the collapsed-surface note"
    assert new["base"]["reachability"] == 1, "the 0-hop breach IS a breach"
    assert new["steps"] == [] and "note" not in new, (
        "no edge carries a path (freq empty) — steps stay honest and empty"
    )

    # (b) a real route + the owned jewel: same cuts, same coverage — only the
    # breach-count differs (fake omits the 0-hop term, new keeps it), which
    # flips the fake's verdict from collapsed to the honest "degraded"
    port = _port([(T1, "MEMBER_OF", DA)], jewels=(DA,), owned=(DA, T1))
    old = old_plan(port, k=2)
    new = plan_cut_sequence(port, k=2)
    assert old["base"]["reachability"] == 1 and old["steps"][0]["projected_verdict"] == "collapsed"
    assert new["base"]["reachability"] == 2
    assert new["steps"][0]["cut"] == {"src": T1, "rel": "MEMBER_OF", "dst": DA}
    assert new["steps"][0]["projected_reachability"] == 1  # the 0-hop breach survives the cut
    assert new["steps"][0]["projected_verdict"] == "degraded"
    assert new["plan_completes_at_step"] is None, "an owned jewel is never collapsible by edge cuts"


def test_snapshot_and_interdict_still_measure_via_port_reachability():
    """Guard: the refactor must not touch snapshot()/interdict() — they keep
    measuring through the port's own reachability() (once per snapshot,
    before+after in interdict; pinned by tests/test_core_edges.py stubs)."""
    calls = []

    class _CountingStub(GraphPort):
        def load(self, graph): ...
        def node_count(self): return 1
        def edge_count(self): return 1
        def mark_owned(self, objectid): ...
        def owned_ids(self): return ["O"]
        def crown_jewels(self): return ["J"]
        def reachability(self, hop_cap: int = 12) -> int:
            calls.append(hop_cap)
            return len(calls)
        def paths_to_jewels(self, objectid, hop_cap: int = 12, ties: bool = False): return []
        def edge_frequency(self, hop_cap: int = 12): return {}
        def add_edge(self, src, dst, rel, props=None): return False
        def cut(self, src, dst, rel): return 1
        def profile(self, query, params=None): return ""
        def receipt(self): return {}

    stub = _CountingStub()
    assert snapshot(stub)["reachability"] == 1
    receipt = interdict(stub, "O", "J", "R")
    assert receipt["before"]["reachability"] == 2
    assert receipt["after"]["reachability"] == 3
    assert len(calls) == 3, "exactly one reachability() per snapshot, two snapshots per interdict"


# ---------------------------------------------------------------------------
# ENGINE equivalence (docker compose up -d / SEVER_FALKOR_HOST=...)
# Graph keys: prefixed sever_audit7_pe_* — dropped in every finally.
# ---------------------------------------------------------------------------

BATCHED_PAIRS_QUERY_TEMPLATE = (
    "UNWIND $pairs AS pair "
    "MATCH (o {{objectid: pair.o}}), (t {{objectid: pair.j}}) "
    "WITH o, t, pair, shortestPath((o)-{pattern}->(t)) AS p "
    "WHERE p IS NOT NULL "
    "RETURN pair.o AS oid, p AS p"
)


class BatchedFalkorPort(FalkorGraphPort):
    """The seam override the falkor backend can adopt verbatim: ONE query
    enumerates every (principal, jewel) pair's canonical path. Engine-
    verified form — the plain `UNWIND $oids AS oid ... {objectid: oid}` is
    REJECTED by the engine ("'oid' not defined"); the pairs-of-maps form
    parses and returns exactly the per-pair loop's paths (pinned below)."""

    def canonical_paths_multi(
        self,
        objectids,
        hop_cap: int = DEFAULT_HOP_CAP,
        jewels=None,
    ) -> dict[str, list[list[tuple[str, str, str]]]]:
        out: dict[str, list[list[tuple[str, str, str]]]] = {oid: [] for oid in objectids}
        if not out:
            return out
        jewel_list = list(jewels) if jewels is not None else self.crown_jewels()
        if not jewel_list:
            return out
        q = BATCHED_PAIRS_QUERY_TEMPLATE.format(pattern=cypher_traversal_pattern(hop_cap))
        params = {"pairs": [{"o": oid, "j": j} for oid in objectids for j in jewel_list]}
        res = self.graph.query(q, params, timeout=30000)
        for row in res.result_set:
            oid = str(row[0])
            hops = _row_to_hops([row[1]])
            # the same guard paths_to_jewels applies (no-op for the
            # engine-enforced canonical form, load-bearing for parity)
            if not hops or len(hops) > hop_cap or any(
                rel not in TRAVERSAL_RELS_SET for _, rel, _ in hops
            ):
                continue
            out.setdefault(oid, []).append(hops)
        return out

    def scratch_copy(self, scratch_name: str) -> "BatchedFalkorPort":
        from falkordb import Graph as _Graph

        client = self.graph.client
        try:
            client.execute_command("GRAPH.DELETE", scratch_name)
        except Exception:
            pass
        client.execute_command("GRAPH.COPY", self.graph_name, scratch_name)
        return BatchedFalkorPort(
            client=_Graph(client=client, name=scratch_name),
            graph_name=scratch_name,
        )


def _batched_view(port: FalkorGraphPort) -> BatchedFalkorPort:
    """A BatchedFalkorPort over the SAME engine graph key as `port`."""
    from falkordb import Graph as _Graph

    return BatchedFalkorPort(
        client=_Graph(client=port.graph.client, name=port.graph_name),
        graph_name=port.graph_name,
    )


def _synth_two_route_port(graph_name: str) -> FalkorGraphPort:
    from tests.test_planning import (  # the audit-pinned synth estate
        S_A1, S_B1, S_DA, S_MID, S_U1, S_ZOE,
    )

    port = make_live_port(graph_name, load_sample=False)
    drop_graph(port, graph_name)
    g = NormalizedGraph()
    for oid, name in ((S_ZOE, "zoe"), (S_A1, "a1"), (S_B1, "b1"),
                      (S_MID, "mid"), (S_U1, "one")):
        g.add_node(oid, "User", {"name": name})
    g.add_node(S_DA, "Group", {"name": "Domain Admins"})
    for src, rel, dst in (
        (S_ZOE, "GENERIC_ALL", S_A1), (S_A1, "MEMBER_OF", S_DA),
        (S_ZOE, "WRITE_DACL", S_B1), (S_B1, "MEMBER_OF", S_DA),
        (S_U1, "GENERIC_ALL", S_MID), (S_MID, "MEMBER_OF", S_DA),
    ):
        g.add_edge(src, dst, rel)
    port.load(g)
    port.mark_owned(S_ZOE)
    return port


class TestPlanEquivalenceEngine:
    pytestmark = [requires_engine]

    @requires_sample
    def test_old_vs_new_plan_receipts_on_sample_estate(self):
        gname = prefixed("sever_audit7_pe_sample")
        port = make_live_port(gname)
        try:
            port.mark_owned(HERO)
            new = plan_cut_sequence(port, k=3)
            old = old_plan(port, k=3)
            assert new == old
            assert new["steps"], "the sample estate plans at least one cut"
        finally:
            drop_graph(port, gname)

    def test_old_vs_new_plan_receipts_on_synth_two_route(self):
        gname = prefixed("sever_audit7_pe_synth")
        port = _synth_two_route_port(gname)
        try:
            new = plan_cut_sequence(port, k=3)
            old = old_plan(port, k=3)
            assert new == old
            assert new["plan_completes_at_step"] == 2
        finally:
            drop_graph(port, gname)

    def test_old_vs_new_plan_on_owned_jewel_estate(self):
        """The 0-hop breach term is load-bearing on the engine: an owned
        crown jewel counts as reached before AND after every cut, in BOTH
        the old two-arm form and the new per-pair derivation."""
        gname = prefixed("sever_audit7_pe_ownjewel")
        port = make_live_port(gname, load_sample=False)
        drop_graph(port, gname)
        try:
            g = NormalizedGraph()
            JG = "S-1-5-21-pe-777-512"   # Group jewel, by RID
            P1 = "S-1-5-21-pe-777-1001"  # a user one hop from the jewel
            P2 = "S-1-5-21-pe-777-1002"
            for oid, label in ((JG, "Group"), (P1, "User"), (P2, "User")):
                g.add_node(oid, label, {"name": oid})
            g.add_edge(P1, P2, "GENERIC_ALL")
            g.add_edge(P2, JG, "MEMBER_OF")
            port.load(g)
            port.mark_owned(P1)
            port.mark_owned(JG)  # the owned JEWEL: 0-hop breach
            new = plan_cut_sequence(port, k=3)
            old = old_plan(port, k=3)
            assert new == old
            assert new["base"]["reachability"] == 2
            for step in new["steps"]:
                # the 0-hop breach survives every cut; only the route dies
                assert step["projected_reachability"] >= 1
            assert new["steps"][-1]["projected_reachability"] == 1
            assert new["plan_completes_at_step"] is None, \
                "an owned jewel is never collapsible by edge cuts"
        finally:
            drop_graph(port, gname)

    @pytest.mark.parametrize("seed", range(8))
    def test_old_vs_new_plan_on_fuzz_micrographs(self, seed):
        rng = random.Random(0xA0D1733 + seed)
        spec = random_micro_graph(rng, f"pe{seed:02d}")
        gname = prefixed(f"sever_audit7_pe_fuzz{seed:02d}")
        port = FalkorGraphPort(graph_name=gname)
        drop_graph(port, gname)
        try:
            port.load(spec.graph)
            if spec.self_loop_oid:
                port.graph.query(
                    "MATCH (n {objectid: $oid}) CREATE (n)-[:MEMBER_OF]->(n)",
                    {"oid": spec.self_loop_oid},
                )
            for oid in spec.owned:
                port.mark_owned(oid)
            new = plan_cut_sequence(port, k=2)
            old = old_plan(port, k=2)
            assert new == old, f"fuzz seed {seed} diverged"
            # derived reachability == the port's own two-arm count, per state
            # the plan actually reasoned about (pre-plan, here)
            if spec.owned:
                jewels = set(port.crown_jewels())
                paths = port.canonical_paths_multi(port.owned_ids(), DEFAULT_HOP_CAP, port.crown_jewels())
                derived = len(
                    {o for o, ps in paths.items() if ps} | (set(port.owned_ids()) & jewels)
                )
                assert derived == port.reachability(DEFAULT_HOP_CAP), seed
        finally:
            drop_graph(port, gname)

    @requires_sample
    @pytest.mark.parametrize("cap", [1, 2, 3, 12])
    def test_derived_reachability_equals_arm_reachability_on_sample(self, cap):
        gname = prefixed("sever_audit7_pe_caps")
        port = make_live_port(gname)
        try:
            port.mark_owned(HERO)
            jewels = port.crown_jewels()
            owned = port.owned_ids()
            paths = port.canonical_paths_multi(owned, cap, jewels)
            derived = len({o for o, ps in paths.items() if ps} | (set(owned) & set(jewels)))
            assert derived == port.reachability(cap)
        finally:
            drop_graph(port, gname)


class TestBatchedSeamEngine:
    """The override the falkor backend can adopt: ONE query enumerates
    exactly what the shipped per-pair loop enumerates."""

    pytestmark = [requires_engine]

    @requires_sample
    @pytest.mark.parametrize("cap", [12, 4])
    def test_batched_enumeration_matches_the_loop_on_sample(self, cap):
        gname = prefixed("sever_audit7_pe_batch")
        port = make_live_port(gname)
        try:
            port.mark_owned(HERO)
            batched = _batched_view(port)
            pool = sorted(set(port.user_objectids()) - set(port.owned_ids()))
            step = max(1, len(pool) // 25) if pool else 1
            ids = port.owned_ids() + pool[::step][:25]
            jewels = port.crown_jewels()
            assert batched.canonical_paths_multi(ids, cap, jewels) == \
                port.canonical_paths_multi(ids, cap, jewels)
            # empty + no-path inputs keep the empty-list convention
            assert batched.canonical_paths_multi([], cap, jewels) == {}
            assert all(not v for v in batched.canonical_paths_multi(
                ["S-1-5-21-pe-nonexistent"], cap, jewels).values())
        finally:
            drop_graph(port, gname)

    @pytest.mark.parametrize("seed", range(4))
    @pytest.mark.parametrize("cap", [12, 3])
    def test_batched_enumeration_matches_the_loop_on_fuzz(self, seed, cap):
        rng = random.Random(0xA0D1733 + seed)
        spec = random_micro_graph(rng, f"peb{seed:02d}")
        gname = prefixed(f"sever_audit7_pe_batchfuzz{seed:02d}")
        port = FalkorGraphPort(graph_name=gname)
        drop_graph(port, gname)
        try:
            port.load(spec.graph)
            if spec.self_loop_oid:
                port.graph.query(
                    "MATCH (n {objectid: $oid}) CREATE (n)-[:MEMBER_OF]->(n)",
                    {"oid": spec.self_loop_oid},
                )
            for oid in spec.owned:
                port.mark_owned(oid)
            batched = _batched_view(port)
            ids = port.owned_ids() or list(spec.nodes)
            jewels = port.crown_jewels()
            assert batched.canonical_paths_multi(ids, cap, jewels) == \
                port.canonical_paths_multi(ids, cap, jewels)
        finally:
            drop_graph(port, gname)

    @requires_sample
    def test_plan_receipts_identical_through_the_batched_seam(self):
        gname = prefixed("sever_audit7_pe_planbatch")
        port = make_live_port(gname)
        try:
            port.mark_owned(HERO)
            via_default = plan_cut_sequence(port, k=3)
            via_batched = plan_cut_sequence(_batched_view(port), k=3)
            assert via_batched == via_default
        finally:
            drop_graph(port, gname)


# ---------------------------------------------------------------------------
# PERF: query counting (deterministic) + wall-time receipts
# ---------------------------------------------------------------------------

def _classify(query: str) -> str:
    if "RETURN DISTINCT o.objectid AS oid" in query:
        return "arm_reachability"
    if "UNWIND $pairs" in query:
        return "batched_pairs"
    if "WITH shortestPath" in query and "RETURN p" in query:
        return "canonical_probe"
    if "ENDS WITH '-512'" in query or "toLower" in query:
        return "crown_jewels"
    if "owned: true" in query:
        return "owned_ids"
    if "DELETE r RETURN" in query:
        return "cut"
    if "MATCH (u:User) RETURN" in query:
        return "user_objectids"
    if "count(" in query:
        return "count"
    return "other"


class _QueryLog:
    """Class-wide patch of falkordb Graph.query — every port (live, scratch,
    batched) in the process is counted."""

    def __init__(self, monkeypatch):
        import falkordb.graph as falkor_graph

        self.calls: list[tuple[str, float]] = []
        original = falkor_graph.Graph.query
        log = self

        def counting_query(self, q, params=None, timeout=None):
            t0 = time.perf_counter()
            res = original(self, q, params, timeout)
            log.calls.append((_classify(q), (time.perf_counter() - t0) * 1000.0))
            return res

        monkeypatch.setattr(falkor_graph.Graph, "query", counting_query)

    def reset(self):
        self.calls.clear()

    def summary(self) -> dict[str, Any]:
        by: dict[str, dict[str, Any]] = {}
        for kind, ms in self.calls:
            d = by.setdefault(kind, {"n": 0, "total_ms": 0.0})
            d["n"] += 1
            d["total_ms"] += ms
        return {
            "total_queries": len(self.calls),
            "total_ms": round(sum(ms for _, ms in self.calls), 1),
            "by_kind": {k: {"n": v["n"], "total_ms": round(v["total_ms"], 1)}
                        for k, v in sorted(by.items())},
        }


class TestPlanPerfEngine:
    pytestmark = [requires_engine, requires_sample]

    @pytest.fixture()
    def sample_port(self):
        gname = prefixed("sever_audit7_pe_perf")
        port = make_live_port(gname)
        port.mark_owned(HERO)
        yield port
        drop_graph(port, gname)

    def test_new_plan_issues_zero_arm_queries(self, sample_port, monkeypatch):
        log = _QueryLog(monkeypatch)

        log.reset()
        old = old_plan(sample_port, k=3)
        old_summary = log.summary()
        assert old_summary["by_kind"].get("arm_reachability", {"n": 0})["n"] >= 4, (
            "the counting harness must see the old plan's arm queries"
        )

        log.reset()
        plan_cut_sequence(sample_port, k=3)
        new_summary = log.summary()
        assert new_summary["by_kind"].get("arm_reachability", {"n": 0})["n"] == 0, (
            "the new plan must never issue the two-arm all-pairs query"
        )
        assert new_summary["total_queries"] < old_summary["total_queries"], (
            f"round-trips must not grow: old={old_summary['total_queries']} "
            f"new={new_summary['total_queries']}"
        )

        log.reset()
        plan_cut_sequence(_batched_view(sample_port), k=3)
        batched_summary = log.summary()
        assert batched_summary["by_kind"].get("arm_reachability", {"n": 0})["n"] == 0
        # the seam is the round-trip lever: one batched query replaces the
        # whole per-principal probe storm (the 3-10x cut the mission wants)
        ratio = old_summary["total_queries"] / batched_summary["total_queries"]
        assert ratio >= 3, (
            f"seam round-trip cut below target: old={old_summary['total_queries']} "
            f"batched={batched_summary['total_queries']} ratio={ratio:.1f}x"
        )

    def test_plan_wall_time_and_receipts(self, sample_port, monkeypatch):
        def run_times(fn, runs=3):
            walls = []
            for _ in range(runs):
                log.reset()
                t0 = time.perf_counter()
                fn()
                walls.append((time.perf_counter() - t0) * 1000.0)
            return walls

        log = _QueryLog(monkeypatch)
        log.reset(); old_walls = run_times(lambda: old_plan(sample_port, k=3))
        log.reset(); new_walls = run_times(lambda: plan_cut_sequence(sample_port, k=3))
        log.reset()
        batched_walls = []
        batched_queries = None
        for _ in range(3):
            log.reset()
            t0 = time.perf_counter()
            plan_cut_sequence(_batched_view(sample_port), k=3)
            batched_walls.append((time.perf_counter() - t0) * 1000.0)
            batched_queries = log.summary()["total_queries"]
        log.reset(); old_plan(sample_port, k=3); old_q = log.summary()
        log.reset(); plan_cut_sequence(sample_port, k=3); new_q = log.summary()

        def stats(walls):
            return {
                "runs_ms": [round(w, 1) for w in walls],
                "median_ms": round(statistics.median(walls), 1),
                "p95_ms": round(statistics.quantiles(walls, n=20)[-1], 1),
                "p99_ms": round(max(walls), 1),
            }

        receipt = {
            "beat": "audit7/perf-scoring — Plan k-cut sequence hot path",
            "estate": "ad_sample estate, hero owned (1480 nodes / 12450 edges, 5 jewels)",
            "engine": {
                "host": os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
                "modules": None,
            },
            "k": 3,
            "old_two_arm_plan": {"wall": stats(old_walls), "queries": old_q},
            "new_per_pair_plan": {"wall": stats(new_walls), "queries": new_q},
            "new_batched_seam_plan": {
                "wall": stats(batched_walls),
                "queries": {"total_queries": batched_queries},
            },
            "targets": {
                "k3_plan_local_ms_max": 1500,
                "roundtrip_cut_vs_old_min_x": 3,
            },
        }
        try:
            receipt["engine"]["modules"] = str(
                sample_port.graph.client.execute_command("MODULE", "LIST")[:1]
            )
            receipt["profile_arm_query"] = sample_port.profile(
                REACHABILITY_ARM_TEMPLATES[0].format(
                    pattern=cypher_traversal_pattern(DEFAULT_HOP_CAP)
                )
            )
            receipt["profile_batched_pairs_query"] = sample_port.profile(
                BATCHED_PAIRS_QUERY_TEMPLATE.format(
                    pattern=cypher_traversal_pattern(DEFAULT_HOP_CAP)
                ),
                None,
            )
        except Exception:
            pass

        # mission target: k=3 plan on the sample estate < 1.5s local
        assert statistics.median(new_walls) < 1500, receipt
        assert statistics.median(batched_walls) < statistics.median(new_walls), (
            "the seam override must not be slower than the default loop"
        )

        out_dir = os.environ.get("SEVER_PERF_RECEIPT_DIR")
        if out_dir:
            path = Path(out_dir) / "perf_plan_equivalence.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(receipt, indent=1), encoding="utf-8")
