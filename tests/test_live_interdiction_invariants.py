"""audit3: INTERDICTION LOGIC DEEP-AUDIT — invariant + property tests, live.

Every test runs against the REAL FalkorDB engine (ryzen / docker compose) on
graph keys sever_audit3_il* ONLY (dropped in finally, verified empty after).

Invariants pinned (audit3 mandate):
  I1  a cut can never INCREASE reachability (property: random cut sequences)
  I2  a receipt's after-state must equal an independent re-query
  I3  a proposed edge must lie on >=1 enumerated path (never a phantom)
  I4  verdict coupling: "collapsed" only when reachability==0 after;
      "degraded" only when >0 after; "no_effect" only when nothing was removed
  I5  add_edge idempotency (grant twice -> one edge, second returns False)
  I6  mark_owned idempotent

Two-arm vs per-pair reachability (both live, plus a DB-free BFS oracle as a
third independent opinion): owned==jewel (0-hop breach), hop_cap 1..13 sweep,
empty owned, ALL nodes owned, a crafted 13-hop path (cap must bind in *..N),
self-loop edges, disconnected jewels, case-varied GA holders.

Randomized micro-graph fuzz: 50 deterministic graphs (2-8 nodes, random
abusable rels, random owned) — all three opinions must agree on every one.

Greedy ranking: the top proposal is never worse than 20 sampled candidates
(path-coverage argmax), and edge_frequency equals an independent enumeration.
"""
from __future__ import annotations

import random

import pytest

from tests.conftest import SAMPLE_DIR, drop_graph, prefixed, requires_engine, requires_sample
from tests.interdiction_fuzz import MicroGraph, oracle_reached, random_micro_graph
from sever.agent.investigator import Investigator
from sever.core.falkor_port import (
    REACHABILITY_ARM_TEMPLATES,
    REACHABILITY_QUERY_TEMPLATE,
    FalkorGraphPort,
)
from sever.core.jewels import DEFAULT_HOP_CAP, TRAVERSAL_RELS_SET, cypher_traversal_pattern
from sever.core.scoring import interdict, rank_cut_candidates, snapshot
from sever.etl.ad_collectors import ABUSABLE_RELS, NormalizedGraph, parse_ad_dir

pytestmark = [requires_engine]

P = "sever_audit3_il"  # graph-key prefix — mandated, deleted after

# live mutations (cut/add_edge) only accept the closed vocabulary the ETL emits
# and the engine chains — the fuzz generator also loads structural rels
# (CONTAINED_BY/PUBLISHED_ON) which are cuttable only via raw Cypher, never
# through the mutation seam
CUTTABLE_RELS = TRAVERSAL_RELS_SET | frozenset(ABUSABLE_RELS)


# ---------------------------------------------------------------------------
# opinion implementations
# ---------------------------------------------------------------------------

def arm_reached_set(port: FalkorGraphPort, hop_cap: int = DEFAULT_HOP_CAP) -> set[str]:
    """Set-valued replica of FalkorGraphPort.reachability (the two-arm form)."""
    reached: set[str] = set()
    pattern = cypher_traversal_pattern(hop_cap)
    for arm in REACHABILITY_ARM_TEMPLATES:
        res = port.graph.query(arm.format(pattern=pattern), timeout=60000)
        reached.update(str(row[0]) for row in res.result_set)
    jewel_set = set(port.crown_jewels())
    reached.update(o for o in port.owned_ids() if o in jewel_set)
    return reached


def per_pair_reached_set(port: FalkorGraphPort, hop_cap: int = DEFAULT_HOP_CAP) -> set[str]:
    """Independent reference: the product's own per-(owned, jewel) existence
    probe, plus the documented owned-jewel 0-hop breach union."""
    jewels = port.crown_jewels()
    jewel_set = set(jewels)
    owned = port.owned_ids()
    reached = {o for o in owned if o in jewel_set}
    q = REACHABILITY_QUERY_TEMPLATE.format(pattern=cypher_traversal_pattern(hop_cap))
    for o in owned:
        if o in jewel_set:
            continue
        for j in jewels:
            res = port.graph.query(q, {"oid": o, "target": j}, timeout=30000)
            if res.result_set and bool(res.result_set[0][0]):
                reached.add(o)
                break
    return reached


def assert_forms_agree(
    port: FalkorGraphPort,
    nodes: dict[str, tuple[str, str]],
    edges: list[tuple[str, str, str]],
    hop_cap: int,
    ctx: str,
) -> set[str]:
    """two-arm == per-pair == DB-free oracle == the port's own count."""
    arm = arm_reached_set(port, hop_cap)
    pair = per_pair_reached_set(port, hop_cap)
    oracle = oracle_reached(nodes, edges, port.owned_ids(), hop_cap)
    assert arm == pair, (
        f"[{ctx}] cap={hop_cap}: two-arm {sorted(arm)} != per-pair {sorted(pair)} "
        f"(missing from arm: {sorted(pair - arm)}, phantom in arm: {sorted(arm - pair)})"
    )
    assert arm == oracle, (
        f"[{ctx}] cap={hop_cap}: two-arm {sorted(arm)} != oracle {sorted(oracle)} "
        f"(arm missing: {sorted(oracle - arm)}, arm phantom: {sorted(arm - oracle)})"
    )
    assert len(arm) == port.reachability(hop_cap), (
        f"[{ctx}] cap={hop_cap}: port.reachability()={port.reachability(hop_cap)} "
        f"disagrees with its own two-arm reached set {sorted(arm)}"
    )
    return arm


def assert_verdict_coupling(receipt: dict, ctx: str) -> None:
    """I4 on any interdict receipt."""
    v, after = receipt["verdict"], receipt["after"]["reachability"]
    if v == "collapsed":
        assert after == 0, f"[{ctx}] 'collapsed' claimed with reachability {after} > 0"
    elif v == "degraded":
        assert after > 0, f"[{ctx}] 'degraded' claimed with reachability {after} == 0"
    elif v == "no_effect":
        assert receipt["cut"]["relationships_removed"] == 0, (
            f"[{ctx}] 'no_effect' claimed with relationships_removed "
            f"{receipt['cut']['relationships_removed']} >= 1"
        )
    else:
        raise AssertionError(f"[{ctx}] unknown verdict {v!r}")


def assert_receipt_honest(receipt: dict, port: FalkorGraphPort, ctx: str) -> None:
    """I1 + I2 on any interdict receipt: after <= before, and after equals an
    independent re-query of every snapshot field."""
    assert receipt["after"]["reachability"] <= receipt["before"]["reachability"], (
        f"[{ctx}] reachability INCREASED after a cut: "
        f"{receipt['before']['reachability']} -> {receipt['after']['reachability']}"
    )
    requery = snapshot(port, DEFAULT_HOP_CAP)
    assert receipt["after"] == requery, (
        f"[{ctx}] receipt after-state {receipt['after']} != independent re-query {requery}"
    )
    assert_verdict_coupling(receipt, ctx)


def _coverage(port: FalkorGraphPort) -> tuple[dict[tuple[str, str, str], int], set[tuple[str, str, str]]]:
    """Independent path-coverage from a fresh enumeration (not edge_frequency)."""
    cov: dict[tuple[str, str, str], int] = {}
    hops: set[tuple[str, str, str]] = set()
    for o in port.owned_ids():
        for path in port.paths_to_jewels(o, DEFAULT_HOP_CAP):
            for hop in path:
                cov[hop] = cov.get(hop, 0) + 1
                hops.add(hop)
    return cov, hops


def assert_greedy_and_proposals(port: FalkorGraphPort, rng: random.Random,
                               spec_edges: list[tuple[str, str, str]], ctx: str) -> None:
    """I3 + greedy ranking: top proposal is the argmax and never worse than
    20 sampled candidates; no proposal is phantom; then ONE gated cut whose
    receipt must satisfy I1/I2/I4."""
    freq = port.edge_frequency(DEFAULT_HOP_CAP)
    if not freq:
        assert rank_cut_candidates(freq) == []
        return
    cov, path_hops = _coverage(port)
    assert cov == freq, f"[{ctx}] edge_frequency {freq} != independent coverage {cov}"
    ranked = rank_cut_candidates(freq, limit=10)
    top = ranked[0]
    assert top["paths_on"] == max(freq.values()), f"[{ctx}] top is not the argmax"
    # I3: every proposal lies on >=1 enumerated path — never phantom
    proposals = Investigator(port).propose(limit=5)
    for p in proposals:
        assert (p["src"], p["rel"], p["dst"]) in path_hops, f"[{ctx}] phantom proposal {p}"
    # greedy: 20 sampled candidates (any graph edge) must not beat the top
    pool = [e for e in spec_edges] or sorted(path_hops)
    for cand in rng.sample(pool, min(20, len(pool))):
        assert cov.get(cand, 0) <= top["paths_on"], (
            f"[{ctx}] candidate {cand} coverage {cov.get(cand, 0)} beats top {top}"
        )
    receipt = Investigator(port).approve_and_cut(
        top["src"], top["dst"], top["rel"], approved_by=f"audit3-{ctx}"
    )
    assert receipt["cut"]["relationships_removed"] >= 1
    assert_receipt_honest(receipt, port, ctx)


# ---------------------------------------------------------------------------
# crafted estate for the edge-case matrix
# ---------------------------------------------------------------------------

JG = "audit3-g-S-1-5-21-77-512"   # Group jewel, RENAMED (SID-based detection)
JG2 = "audit3-g-S-1-5-21-77-519"  # Group jewel #2, DISCONNECTED (no in-edges)
AZ1 = "audit3-az-1"               # GA holder, exact case
AZ2 = "audit3-az-2"               # GA holder, lowercase — anti-evasion case
AZ3 = "audit3-az-3"               # GA holder, UPPERCASE, DISCONNECTED
AZD = "audit3-az-9"               # GA look-alike decoy (truncated suffix)
O1 = "audit3-o1"                   # owned: 1 hop to AZ2 (case-varied holder)
O2 = "audit3-o2"                   # owned: 2 hops to AZ1
O3 = "audit3-o3"                   # owned: 1 hop to the DECOY only
MID = "audit3-mid-o2"
NOISE = "audit3-noise"


def _matrix_graph() -> MicroGraph:
    g = NormalizedGraph()
    nodes: dict[str, tuple[str, str]] = {}
    edges: list[tuple[str, str, str]] = []

    def node(oid: str, label: str, name: str) -> None:
        g.add_node(oid, label, {"name": name})
        nodes[oid] = (label, name)

    def edge(s: str, rel: str, d: str) -> None:
        if g.add_edge(s, d, rel, {"source": "audit3-matrix"}):
            edges.append((s, rel, d))

    node(JG, "Group", "TotallyNotAdmins")
    node(JG2, "Group", "AlsoNotAdmins")
    node(AZ1, "AZUser", "ga1-GlobalAdministrator")
    node(AZ2, "AZUser", "ga2-globaladministrator")
    node(AZ3, "AZUser", "ga3-GLOBALADMINISTRATOR")
    node(AZD, "AZUser", "ga9-GlobalAdministrato")  # NOT a holder
    node(O1, "User", "o1"); node(O2, "User", "o2"); node(O3, "User", "o3")
    node(MID, "User", "mid"); node(NOISE, "User", "noise")

    edge(O1, "DCSYNC", AZ2)                 # breach path to a case-varied holder
    edge(O2, "MEMBER_OF", MID)
    edge(MID, "GENERIC_WRITE", AZ1)
    edge(O3, "MEMBER_OF", AZD)              # path to a decoy: never a breach
    edge(NOISE, "CONTAINED_BY", JG)         # structural route: not chainable
    # W-chains: owner Wk has exactly k MEMBER_OF hops to JG
    for k in (1, 3, 6, 9, 12, 13):
        owner = f"audit3-w{k}"
        node(owner, "User", f"w{k}")
        prev = owner
        for i in range(k - 1):
            m = f"audit3-mid-w{k}-{i}"
            node(m, "User", f"w{k}-m{i}")
            edge(prev, "MEMBER_OF", m)
            prev = m
        edge(prev, "MEMBER_OF", JG)
    return MicroGraph(g, nodes, edges, [], None)


MATRIX_OWNED = [O1, O2, O3, "audit3-w1", "audit3-w3", "audit3-w6",
                "audit3-w9", "audit3-w12", "audit3-w13", JG]


@pytest.fixture()
def matrix_port():
    gname = prefixed(f"{P}_matrix")
    port = FalkorGraphPort(graph_name=gname)
    drop_graph(port, gname)
    port.load(_matrix_graph().graph)
    yield port
    drop_graph(port, gname)


def test_two_arm_edge_case_matrix(matrix_port):
    """Owned==jewel / cap sweep 1..13 / empty owned / all owned / 13-hop path
    binding / self-loops / disconnected jewels / case-varied GA holders."""
    port = matrix_port
    spec = _matrix_graph()
    assert port.crown_jewels() == sorted([JG, JG2, AZ1, AZ2, AZ3])

    # --- empty owned: no breach ---
    assert port.owned_ids() == []
    assert port.reachability() == 0
    assert_forms_agree(port, spec.nodes, spec.edges, DEFAULT_HOP_CAP, "matrix/empty")

    # --- self-loops in the substrate must not perturb any form ---
    for oid in (MID, JG):
        port.graph.query(
            "MATCH (n {objectid: $oid}) CREATE (n)-[:MEMBER_OF]->(n)", {"oid": oid}
        )
    assert_forms_agree(port, spec.nodes, spec.edges, DEFAULT_HOP_CAP, "matrix/selfloop")
    r = port.reachability()
    assert port.cut(MID, MID, "MEMBER_OF") == 1  # cutting a self-loop is inert
    assert port.reachability() == r

    # --- ALL nodes owned ---
    for oid in spec.nodes:
        port.mark_owned(oid)
    assert port.owned_ids() == sorted(spec.nodes)
    for cap in (1, 6, 12, 13):
        assert_forms_agree(port, spec.nodes, spec.edges, cap, f"matrix/all-owned/cap{cap}")

    # --- fresh reload, then the pinned owner set ---
    drop_graph(port, prefixed(f"{P}_matrix"))
    port2 = FalkorGraphPort(graph_name=prefixed(f"{P}_matrix"))
    port2.load(_matrix_graph().graph)
    try:
        for oid in MATRIX_OWNED:
            port2.mark_owned(oid)
        assert sorted(port2.owned_ids()) == sorted(MATRIX_OWNED)
        # owned==jewel (0-hop breach): JG itself is owned — all three opinions
        # must count it, and the raw probe alone must NOT (the union is
        # load-bearing, shortestPath needs >=1 hop for a self-pair)
        probe = REACHABILITY_QUERY_TEMPLATE.format(
            pattern=cypher_traversal_pattern(DEFAULT_HOP_CAP))
        res = port2.graph.query(probe, {"oid": JG, "target": JG}, timeout=30000)
        assert not (res.result_set and bool(res.result_set[0][0])), (
            "self-pair probe unexpectedly hit — 0-hop breach handling changed"
        )
        for cap in range(1, 14):  # full sweep: does the arm form EVER disagree?
            arm = assert_forms_agree(port2, spec.nodes, spec.edges, cap, f"matrix/cap{cap}")
            # cap boundary pins: chains of 1,3,6,9,12 cross at their length
            expected = {"audit3-o1", "audit3-w1", JG}
            for k, oid in ((3, "audit3-w3"), (6, "audit3-w6"), (9, "audit3-w9"), (12, "audit3-w12")):
                if cap >= k:
                    expected.add(oid)
            if cap >= 2:
                expected.add("audit3-o2")
            if cap >= 13:
                expected.add("audit3-w13")  # 13-hop path: only at cap 13
            assert arm == expected, f"[matrix/cap{cap}] {sorted(arm)} != {sorted(expected)}"
        # the 13-hop chain: UNREACHABLE at cap 12, reachable at 13 — the cap
        # binds in the *..12 form, and the chain is genuinely connected
        assert "audit3-w13" not in assert_forms_agree(port2, spec.nodes, spec.edges, 12, "matrix/w13")
        assert "audit3-w13" in assert_forms_agree(port2, spec.nodes, spec.edges, 13, "matrix/w13")
        # disconnected jewels JG2/AZ3 and the decoy target AZD never count
        arm12 = assert_forms_agree(port2, spec.nodes, spec.edges, 12, "matrix/final")
        assert not (arm12 & {"audit3-o3"}), "decoy target must never be a breach"
        # greedy + proposal + receipt invariants on the crafted estate
        assert_greedy_and_proposals(port2, random.Random(77), spec.edges, "matrix/greedy")
    finally:
        drop_graph(port2, f"{P}_matrix")


# ---------------------------------------------------------------------------
# verdict matrix (I4) + receipt re-query (I2) — deterministic cuts
# ---------------------------------------------------------------------------

def test_verdict_matrix_live():
    gname = prefixed(f"{P}_verdict")
    port = FalkorGraphPort(graph_name=gname)
    drop_graph(port, gname)
    try:
        g = NormalizedGraph()
        JV = "audit3-v-S-1-5-21-88-512"  # Group jewel
        for oid, label in ((JV, "Group"), ("audit3-p1", "User"), ("audit3-p2", "User"),
                           ("audit3-n1", "User"), ("audit3-n2", "User")):
            g.add_node(oid, label, {"name": oid})
        g.add_edge("audit3-p1", JV, "MEMBER_OF")
        g.add_edge("audit3-p2", JV, "DCSYNC")
        g.add_edge("audit3-n1", "audit3-n2", "GENERIC_WRITE")  # off-path noise
        port.load(g)
        port.mark_owned("audit3-p1")
        port.mark_owned("audit3-p2")
        assert port.reachability() == 2

        # partial interdiction 2 -> 1: NOT collapsed — degraded (I4 regression)
        r1 = interdict(port, "audit3-p2", JV, "DCSYNC")
        assert r1["before"]["reachability"] == 2 and r1["after"]["reachability"] == 1
        assert r1["cut"]["relationships_removed"] == 1
        assert r1["verdict"] == "degraded", (
            f"partial drop 2->1 mislabeled {r1['verdict']!r} — 'collapsed' is only "
            "ever claimed on measured zero"
        )
        assert_receipt_honest(r1, port, "verdict/partial")

        # full interdiction 1 -> 0: collapsed
        r2 = interdict(port, "audit3-p1", JV, "MEMBER_OF")
        assert r2["after"]["reachability"] == 0
        assert r2["verdict"] == "collapsed"
        assert_receipt_honest(r2, port, "verdict/collapse")

        # cut on an ALREADY-collapsed surface (0 -> 0, edge removed): must not
        # claim "degraded" — degraded only when reachability > 0 after
        r3 = interdict(port, "audit3-n1", "audit3-n2", "GENERIC_WRITE")
        assert r3["cut"]["relationships_removed"] == 1
        assert r3["before"]["reachability"] == r3["after"]["reachability"] == 0
        assert r3["verdict"] != "degraded"
        assert r3["verdict"] == "collapsed", (
            f"0->0 cut with an edge removed mislabeled {r3['verdict']!r}"
        )
        assert_receipt_honest(r3, port, "verdict/zero-state")

        # ghost cut: nothing removed -> no_effect, before == after
        r4 = interdict(port, "audit3-p1", JV, "MEMBER_OF")
        assert r4["cut"]["relationships_removed"] == 0
        assert r4["before"] == r4["after"]
        assert r4["verdict"] == "no_effect"
        assert_receipt_honest(r4, port, "verdict/ghost")

        # port.receipt() too must equal a fresh independent re-query
        rec = port.receipt()
        assert rec["reachability"] == port.reachability()
        assert rec["owned"] == port.owned_ids()
        assert rec["crown_jewels"] == port.crown_jewels()
        assert rec["nodes"] == port.node_count()
        assert rec["edges"] == port.edge_count()
    finally:
        drop_graph(port, gname)


# ---------------------------------------------------------------------------
# idempotency (I5, I6)
# ---------------------------------------------------------------------------

def test_add_edge_and_mark_owned_idempotent():
    gname = prefixed(f"{P}_idem")
    port = FalkorGraphPort(graph_name=gname)
    drop_graph(port, gname)
    try:
        g = NormalizedGraph()
        for oid in ("audit3-a", "audit3-b", "audit3-c"):
            g.add_node(oid, "User", {"name": oid})
        port.load(g)
        e0 = port.edge_count()

        # I5: grant twice -> ONE edge, second returns False
        assert port.add_edge("audit3-a", "audit3-b", "GENERIC_ALL") is True
        n1 = port.graph.query(
            "MATCH (a {objectid: 'audit3-a'})-[r:GENERIC_ALL]->(b {objectid: 'audit3-b'}) "
            "RETURN count(r)", timeout=60000).result_set[0][0]
        assert n1 == 1
        assert port.edge_count() == e0 + 1
        assert port.add_edge("audit3-a", "audit3-b", "GENERIC_ALL",
                             {"source": "second-grant"}) is False
        assert port.add_edge("audit3-a", "audit3-b", "GENERIC_ALL") is False
        n2 = port.graph.query(
            "MATCH (a {objectid: 'audit3-a'})-[r:GENERIC_ALL]->(b {objectid: 'audit3-b'}) "
            "RETURN count(r)", timeout=60000).result_set[0][0]
        assert n2 == 1, f"re-grant created a duplicate edge (count={n2})"
        assert port.edge_count() == e0 + 1

        # a different rel is a DIFFERENT edge (parallel rels are allowed)
        assert port.add_edge("audit3-a", "audit3-b", "MEMBER_OF") is True
        assert port.edge_count() == e0 + 2
        assert port.cut("audit3-a", "audit3-b", "GENERIC_ALL") == 1
        assert port.cut("audit3-a", "audit3-b", "GENERIC_ALL") == 0  # gone
        assert port.edge_count() == e0 + 1  # MEMBER_OF survives

        # contract edges: absent endpoint / self-edge / unknown rel
        assert port.add_edge("audit3-ghost", "audit3-b", "DCSYNC") is False
        assert port.edge_count() == e0 + 1
        assert port.add_edge("audit3-a", "audit3-a", "OWNS") is False
        with pytest.raises(ValueError):
            port.add_edge("audit3-a", "audit3-b", "generic_all")  # not in vocabulary

        # I6: mark_owned is idempotent
        assert port.owned_ids() == []
        port.mark_owned("audit3-b")
        assert port.owned_ids() == ["audit3-b"]
        port.mark_owned("audit3-b")
        assert port.owned_ids() == ["audit3-b"]
        port.mark_owned("audit3-a")
        assert port.owned_ids() == ["audit3-a", "audit3-b"]
        r_before = port.reachability()
        port.mark_owned("audit3-a")  # re-mark must be metrically invisible
        assert port.owned_ids() == ["audit3-a", "audit3-b"]
        assert port.reachability() == r_before
    finally:
        drop_graph(port, gname)


# ---------------------------------------------------------------------------
# randomized micro-graph fuzz (50 deterministic seeds)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("seed", range(50))
def test_micrograph_fuzz_invariants(seed):
    rng = random.Random(0xA0D1733 + seed)
    spec = random_micro_graph(rng, f"f{seed:02d}")
    gname = prefixed(f"{P}_fuzz{seed:02d}")
    port = FalkorGraphPort(graph_name=gname)
    drop_graph(port, gname)
    try:
        port.load(spec.graph)
        if spec.self_loop_oid:  # raw self-loop in the substrate
            port.graph.query(
                "MATCH (n {objectid: $oid}) CREATE (n)-[:MEMBER_OF]->(n)",
                {"oid": spec.self_loop_oid},
            )
        for oid in spec.owned:
            port.mark_owned(oid)
        if spec.owned:
            port.mark_owned(spec.owned[0])  # idempotent re-mark is invisible

        # form agreement: default cap, a short cap, and a full sweep every 5th
        assert_forms_agree(port, spec.nodes, spec.edges, DEFAULT_HOP_CAP, f"fuzz{seed}")
        assert_forms_agree(port, spec.nodes, spec.edges, 3, f"fuzz{seed}")
        if seed % 5 == 0:
            for cap in range(1, 13):
                assert_forms_agree(port, spec.nodes, spec.edges, cap, f"fuzz{seed}")

        # I1: random cuts can never increase reachability
        r_before = port.reachability()
        live_edges = [e for e in spec.edges if e[1] in CUTTABLE_RELS]
        rng.shuffle(live_edges)
        for (s, rel, d) in live_edges[:3]:
            port.cut(s, d, rel)
            r_after = port.reachability()
            assert r_after <= r_before, (
                f"[fuzz{seed}] cut {s}-[{rel}]->{d} raised reachability {r_before}->{r_after}"
            )
            r_before = r_after
        if spec.self_loop_oid:
            r = port.reachability()
            assert port.cut(spec.self_loop_oid, spec.self_loop_oid, "MEMBER_OF") == 1
            assert port.reachability() == r, f"[fuzz{seed}] self-loop cut changed the metric"

        # I3 + greedy + receipt invariants (when paths exist post-cuts)
        assert_greedy_and_proposals(port, rng, spec.edges, f"fuzz{seed}")
    finally:
        drop_graph(port, gname)


# ---------------------------------------------------------------------------
# the real sample estate (hero principal) — same three-opinion agreement
# ---------------------------------------------------------------------------

def _fetch_all_edges(port: FalkorGraphPort) -> list[tuple[str, str, str]]:
    """Every edge, paginated — FalkorDB truncates result sets at 10,000 rows
    (live-measured on the 12,450-edge sample estate: an unpaginated fetch
    silently returned 10,000). SKIP/LIMIT pages collect the complete list."""
    edges: list[tuple[str, str, str]] = []
    skip = 0
    while True:
        page = port.graph.query(
            "MATCH (a)-[r]->(b) "
            "RETURN a.objectid, type(r), b.objectid "
            "ORDER BY a.objectid, type(r), b.objectid "
            "SKIP $skip LIMIT 4000",
            {"skip": skip}, timeout=120000,
        ).result_set
        if not page:
            break
        edges.extend((str(r[0]), str(r[1]), str(r[2])) for r in page)
        if len(page) < 4000:
            break
        skip += 4000
    return edges


@requires_sample
def test_sample_estate_two_arm_vs_per_pair_vs_oracle():
    gname = prefixed(f"{P}_sample")
    port = FalkorGraphPort(graph_name=gname)
    drop_graph(port, gname)
    try:
        if port.node_count() == 0:
            port.load(parse_ad_dir(SAMPLE_DIR))
        groups = [str(r[0]) for r in port.graph.query(
            "MATCH (g:Group) RETURN g.objectid", timeout=120000).result_set]
        az = [(str(r[0]), str(r[1] or "")) for r in port.graph.query(
            "MATCH (u:AZUser) RETURN u.objectid, u.name", timeout=120000).result_set]
        nodes: dict[str, tuple[str, str]] = {oid: ("Group", "") for oid in groups}
        nodes.update({oid: ("AZUser", name) for oid, name in az})
        edges = _fetch_all_edges(port)
        assert len(edges) == port.edge_count(), (
            f"edge fetch incomplete: {len(edges)} of {port.edge_count()} — "
            "raise the pagination ceiling if the estate outgrows it"
        )
        for s, _, d in edges:
            nodes.setdefault(s, ("Other", ""))
            nodes.setdefault(d, ("Other", ""))
        hero = "S-1-5-21-2697957641-2271029196-387917394-2110"
        extra = [str(r[0]) for r in port.graph.query(
            "MATCH (u:User) RETURN u.objectid ORDER BY u.objectid LIMIT 2",
            timeout=120000).result_set]
        for oid in [hero] + extra:
            if oid:
                port.mark_owned(oid)
        assert port.owned_ids(), "expected marked sample principals"
        assert_forms_agree(port, nodes, edges, DEFAULT_HOP_CAP, "sample")
        assert_forms_agree(port, nodes, edges, 4, "sample")
        assert_greedy_and_proposals(port, random.Random(42), edges, "sample")
    finally:
        drop_graph(port, gname)
