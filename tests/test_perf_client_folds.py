"""audit7/perf-client — round-trip fold pins for sever/core/falkor_port.py.

The perf mission: /api/state on the sample estate went from ~11 sequential
engine round-trips to <= 3 by folding the accessor fan-out into ONE combined
snapshot statement (ESTATE_SNAPSHOT_QUERY), keeping the two reachability arms
byte-identical but concurrent, folding the per-jewel canonical path queries
into one statement, and folding edge_frequency's owned x jewels fan-out into
one UNWIND statement.

Every fold is pinned here as EQUIVALENT to the legacy per-query forms:

DB-free section (always runs):
- stub ports (injected clients, no ``.client`` attr) keep the EXACT legacy
  per-query call sequence — the existing wire-shape pins stay load-bearing;
- SEVER_FALKOR_SNAPSHOT_TTL_MS=0 disables the folds entirely (legacy code
  path, selectable per deployment);
- the traffic proxy invalidates the snapshot on write-clause queries and on
  raw execute_command (out-of-band GRAPH.DELETE must never be served from
  cache);
- the round-trip counters see every query.

Engine section (requires_engine + requires_sample, falkordb 6.0.0):
- every folded accessor == an independent re-query of the documented
  single-purpose queries (the values /api/state used to pay 6 round-trips
  for, computed again the old way);
- paths_to_jewels == the per-jewel canonical loop (oracle), same order;
- edge_frequency == the legacy owned x jewels double loop (oracle),
  insertion-order-identical dict;
- interdict's after-receipt == an independent re-query (the receipt-honesty
  invariant, same shape as test_live_interdiction_invariants);
- invalidation: mark_owned / add_edge / cut / raw CREATE / drop_graph are all
  visible to the very next read — zero stale answers;
- THE TARGET PIN: the exact /api/state accessor sequence costs <= 3 engine
  round-trips on the sample estate (was 11 — a regression to the fan-out
  fails the suite);
- the API response itself: /api/state through the real handler == the dict
  the legacy queries produce (identical API response contract).
"""
from __future__ import annotations

import os

import pytest

from tests.conftest import drop_graph, make_live_port, prefixed, requires_engine, requires_sample
from sever.core.falkor_port import (
    AZ_JEWELS_QUERY,
    CANONICAL_PATH_QUERY_TEMPLATE,
    EDGE_FREQ_BATCH_QUERY_TEMPLATE,
    ESTATE_SNAPSHOT_QUERY,
    JEWELS_QUERY,
    OWNED_QUERY,
    PATHS_BATCH_QUERY_TEMPLATE,
    PER_OWNED_REACHABILITY_ARM_TEMPLATES,
    REACHABILITY_ARM_TEMPLATES,
    REACHABILITY_QUERY_TEMPLATE,
    FalkorGraphPort,
    _row_to_hops,
)
from sever.core.jewels import DEFAULT_HOP_CAP, TRAVERSAL_RELS_SET, cypher_traversal_pattern

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"  # T1_TONYMONTANA@PHANTOM.CORP

P = "sever_audit7_client"


# ---------------------------------------------------------------------------
# DB-free: fold gating, proxy behavior, counters
# ---------------------------------------------------------------------------


class _R:
    def __init__(self, rows):
        self.result_set = rows


class _RecordingClient:
    """Bare redis-client stand-in for the raw execute_command path."""

    def __init__(self):
        self.commands: list[tuple] = []
        self.module_list: list | None = None  # canned MODULE LIST response

    def execute_command(self, *args, **kwargs):
        self.commands.append(args)
        if args[:2] == ("MODULE", "LIST") and self.module_list is not None:
            return self.module_list
        return b"OK"


class _LiveShapedGraph:
    """Stand-in with a ``.client`` attr — the fold-machinery gate sees this
    as a real client, so the fold code paths run DB-free. Answers BOTH the
    combined snapshot form and the legacy single-purpose queries from one
    canned estate, so fallback paths are exercisable without an engine."""

    def __init__(self, owned=("o1",), ad=("j-512",), az=("az-ga",), nodes=7, edges=9):
        self.client = _RecordingClient()
        self.calls: list[tuple[str, object]] = []
        self._estate = {
            "owned": list(owned), "ad": list(ad), "az": list(az),
            "nodes": nodes, "edges": edges,
        }

    def query(self, query, params=None, timeout=None):
        self.calls.append((query, params))
        e = self._estate
        if query == ESTATE_SNAPSHOT_QUERY:
            return _R([[
                e["owned"], e["ad"], e["az"], e["nodes"], e["edges"],
            ]])
        if "count(n)" in query:
            return _R([[e["nodes"]]])
        if "count(r)" in query:
            return _R([[e["edges"]]])
        if query == OWNED_QUERY:
            return _R([[o] for o in e["owned"]])
        if query == JEWELS_QUERY:
            return _R([[j] for j in e["ad"]])
        if query == AZ_JEWELS_QUERY:
            return _R([[j] for j in e["az"]])
        return _R([])


def test_stub_without_client_attr_keeps_legacy_sequence():
    # the classic wire-shape stubs (test_guard._SequenceGraph shape) have no
    # .client — the folds must be INERT there, so the existing call-order
    # pins keep holding
    class _Seq:
        def __init__(self):
            self.calls = []

        def query(self, q, params=None, timeout=None):
            self.calls.append(q)
            return _R([[0]])

    stub = _Seq()
    port = FalkorGraphPort(client=stub)
    assert port._fold_active is False
    port.node_count()
    assert "MATCH (n) RETURN count(n)" in stub.calls[0]  # the legacy query


def test_ttl_zero_disables_folds(monkeypatch):
    monkeypatch.setenv("SEVER_FALKOR_SNAPSHOT_TTL_MS", "0")
    g = _LiveShapedGraph()
    port = FalkorGraphPort(client=g)
    assert port._fold_active is False
    assert port.node_count() == 7
    assert port.edge_count() == 9
    assert all("count(" in q for q, _ in g.calls)  # legacy single-purpose forms only


def test_folded_accessors_serve_one_snapshot_row():
    g = _LiveShapedGraph()
    port = FalkorGraphPort(client=g)
    assert port._fold_active is True
    assert port.node_count() == 7
    assert port.edge_count() == 9
    assert port.owned_ids() == ["o1"]
    assert port.crown_jewels() == ["az-ga", "j-512"]
    snapshot_queries = [q for q, _ in g.calls if q == ESTATE_SNAPSHOT_QUERY]
    assert len(snapshot_queries) == 1, "one combined statement serves all accessors"
    assert len(g.calls) == 1


def test_snapshot_ttl_expiry_refetches():
    g = _LiveShapedGraph()
    port = FalkorGraphPort(client=g)
    assert port.node_count() == 7
    # simulate the TTL window having elapsed since the cached fetch
    port._snapshot_at = 0.0
    assert port.edge_count() == 9
    assert len([q for q, _ in g.calls if q == ESTATE_SNAPSHOT_QUERY]) == 2


def test_write_clause_query_invalidates_snapshot():
    g = _LiveShapedGraph()
    port = FalkorGraphPort(client=g)
    assert port.node_count() == 7
    # a raw write issued through port.graph (the way app code / fixtures
    # mutate outside the port methods) must drop the snapshot first
    g._estate["edges"] = 11
    port.graph.query("CREATE (x:User {objectid: 'x'})")
    assert port.edge_count() == 11, "write-clause query must invalidate the snapshot"
    assert len(g.calls) == 3  # snapshot, write, legacy re-read


def test_readonly_query_does_not_invalidate():
    g = _LiveShapedGraph()
    port = FalkorGraphPort(client=g)
    assert port.node_count() == 7
    port.graph.query("MATCH (n) RETURN n.objectid")  # a read: no write clause
    g._estate["edges"] = 11  # only visible on a REFETCH
    assert port.edge_count() == 9, "read-only queries must not drop the burst cache"


def test_raw_execute_command_invalidates_snapshot():
    g = _LiveShapedGraph()
    port = FalkorGraphPort(client=g)
    assert port.node_count() == 7
    g._estate["edges"] = 11
    # out-of-band command through the wrapped client (drop_graph's shape)
    port.graph.client.execute_command("GRAPH.DELETE", "whatever")
    assert port.edge_count() == 11, "a raw command may be a mutation — invalidate"
    assert len(g.client.commands) == 1


def test_rt_counters_see_every_query():
    g = _LiveShapedGraph()
    port = FalkorGraphPort(client=g)
    port.node_count()
    port.crown_jewels()
    port.graph.client.execute_command("GRAPH.INFO")
    rec = port.rt_receipt()
    assert rec["query_count"] == 1
    assert rec["command_count"] == 1
    assert rec["roundtrips"] == 2
    assert rec["queries"] and "GRAPH.QUERY" in rec["queries"][0]
    port.rt_reset()
    assert port.rt_receipt()["roundtrips"] == 0


def test_mutation_methods_invalidate():
    g = _LiveShapedGraph()
    port = FalkorGraphPort(client=g)
    assert port.node_count() == 7
    assert port._snapshot is not None
    port.mark_owned("x")       # mutation -> invalidates
    assert port._snapshot is None
    port.node_count()
    assert port._snapshot is not None
    port.cut("a", "b", "MEMBER_OF")
    assert port._snapshot is None
    port.node_count()
    port.add_edge("a", "b", "GENERIC_ALL")
    assert port._snapshot is None


def test_engine_version_probe_parsing_and_conservative_default():
    # MODULE LIST parsing: the falkordb 'graph' module version selects the
    # cross-product fold forms; a failed probe must read as 0 (conservative —
    # legacy per-pair forms everywhere, never a wrong fast answer)
    g = _LiveShapedGraph()
    g.client.module_list = [
        ["name", "falkordbe", "ver", 10000, "path", "x.so", "args", []],
        ["name", "graph", "ver", 60000, "path", "falkordb.so", "args", []],
    ]
    port = FalkorGraphPort(client=g)
    assert port._probe_engine_version() == 60000
    assert port._modern_engine is True

    g2 = _LiveShapedGraph()
    port2 = FalkorGraphPort(client=g2)  # client answers b'OK' to everything
    assert port2._probe_engine_version() == 0
    assert port2._modern_engine is False

    g3 = _LiveShapedGraph()
    g3.client.module_list = [["name", "graph", "ver", 42200, "path", "f.so", "args", []]]
    port3 = FalkorGraphPort(client=g3)
    assert port3._probe_engine_version() == 42200
    assert port3._modern_engine is False  # the managed Cloud 4.22.0 family


def test_fold_constants_mirror_legacy_predicates_dbfree():
    # structure pins: the folds carry EXACTLY the documented predicates
    assert "g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519'" in ESTATE_SNAPSHOT_QUERY
    assert "toLower(u.name) ENDS WITH '-globaladministrator'" in ESTATE_SNAPSHOT_QUERY
    assert "OPTIONAL MATCH" in ESTATE_SNAPSHOT_QUERY  # empty-estate safety
    for tpl in (PATHS_BATCH_QUERY_TEMPLATE, EDGE_FREQ_BATCH_QUERY_TEMPLATE):
        assert "(t:Group AND (t.objectid ENDS WITH '-512'" in tpl
        assert "toLower(t.name) ENDS WITH '-globaladministrator'" in tpl
        assert "shortestPath((o)-{pattern}->(t))" in tpl
    # the edge-frequency batch uses the reachability arms' owned-set predicate
    assert "MATCH (o {{owned: true}})" in EDGE_FREQ_BATCH_QUERY_TEMPLATE
    assert EDGE_FREQ_BATCH_QUERY_TEMPLATE.format(pattern="[:X]").startswith(
        "MATCH (o {owned: true}) MATCH (t) WHERE"
    )
    # arms unchanged (the README forms are the live forms)
    group_arm, az_arm = REACHABILITY_ARM_TEMPLATES
    assert "Group" in group_arm and "AZUser" not in group_arm
    assert "toLower(t.name) ENDS WITH '-globaladministrator'" in az_arm
    # the per-owned arms mirror the all-owned arms exactly, principal-bound
    for all_owned, per_owned, label in zip(
        REACHABILITY_ARM_TEMPLATES, PER_OWNED_REACHABILITY_ARM_TEMPLATES, ("Group", "AZUser")
    ):
        assert f"MATCH (o {{owned: true}}), (t:{label})" in all_owned.format(pattern="[:X]")
        assert f"MATCH (o {{objectid: $oid}}), (t:{label})" in per_owned.format(pattern="[:X]")
        # same predicates, same hop-cap slot, same RETURN — only the binding differs
        assert all_owned.split("WHERE", 1)[1] == per_owned.split("WHERE", 1)[1]


# ---------------------------------------------------------------------------
# Engine: equivalence of every fold against the legacy per-query forms
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def port():
    p = make_live_port(prefixed(f"{P}_sample"))
    p.mark_owned(HERO)
    yield p
    drop_graph(p, prefixed(f"{P}_sample"))


def _legacy_counts(port: FalkorGraphPort) -> tuple[int, int]:
    nodes = int(port.graph.query("MATCH (n) RETURN count(n)").result_set[0][0])
    edges = int(port.graph.query("MATCH ()-[r]->() RETURN count(r)").result_set[0][0])
    return nodes, edges


def _legacy_jewels(port: FalkorGraphPort) -> list[str]:
    jewels = [str(r[0]) for r in port.graph.query(JEWELS_QUERY).result_set]
    jewels += [str(r[0]) for r in port.graph.query(AZ_JEWELS_QUERY).result_set]
    return sorted(jewels)


def _legacy_owned(port: FalkorGraphPort) -> list[str]:
    return sorted(str(r[0]) for r in port.graph.query(OWNED_QUERY).result_set)


def _legacy_paths(port: FalkorGraphPort, oid: str, hop_cap: int) -> list[list[tuple[str, str, str]]]:
    pattern = cypher_traversal_pattern(hop_cap)
    out: list[list[tuple[str, str, str]]] = []
    for jewel in _legacy_jewels(port):
        res = port.graph.query(
            CANONICAL_PATH_QUERY_TEMPLATE.format(pattern=pattern),
            {"oid": oid, "target": jewel},
            timeout=30000,
        ).result_set
        for row in res:
            hops = _row_to_hops(row)
            if hops and len(hops) <= hop_cap and all(
                rel in TRAVERSAL_RELS_SET for _, rel, _ in hops
            ):
                out.append(hops)
    return out


@requires_engine
@requires_sample
def test_fold_is_active_on_the_real_engine(port):
    # the whole receipt chain below only means the claimed thing if the fold
    # actually engaged on this engine — a silent fallback must be LOUD here
    assert port._fold_active is True, (
        "folds disabled on this engine (capability fallback fired?) — "
        "round-trip targets below are not being tested"
    )


@requires_engine
@requires_sample
def test_snapshot_accessors_equal_legacy_requery(port):
    nodes, edges = _legacy_counts(port)
    assert port.node_count() == nodes
    assert port.edge_count() == edges
    assert port.owned_ids() == _legacy_owned(port)
    assert port.crown_jewels() == _legacy_jewels(port)
    # each accessor returned exactly what its documented single-purpose
    # query returns — checked via independent re-queries issued AFTER the
    # folded reads (the snapshot cache never touched the oracles)


@requires_engine
@requires_sample
def test_reachability_equals_two_arm_replica(port):
    pattern = cypher_traversal_pattern(DEFAULT_HOP_CAP)
    reached = set()
    for arm in REACHABILITY_ARM_TEMPLATES:
        reached.update(
            str(r[0])
            for r in port.graph.query(arm.format(pattern=pattern), timeout=60000).result_set
        )
    jewels = set(_legacy_jewels(port))
    reached.update(o for o in _legacy_owned(port) if o in jewels)
    assert port.reachability() == len(reached)


@requires_engine
@requires_sample
def test_per_owned_arms_match_per_pair_reference(port):
    """The per-owned arm form (used on engines < falkordb 6.0.0, where the
    all-owned cross form undercounts with 2+ owned principals — live-measured
    on the managed Cloud 4.22.0: 2 owned -> 0 reachable vs the per-pair
    probe's 1) must classify EVERY principal exactly as the product's own
    per-pair existence probe does. Pinned here on the local engine with a
    mixed estate: one reaching principal and one that does not reach."""
    some_user = sorted(set(port.user_objectids()) - set(port.owned_ids()))[0]
    port.mark_owned(some_user)  # a second owned principal (does not reach)
    try:
        owned = port.owned_ids()
        jewels = _legacy_jewels(port)
        pattern = cypher_traversal_pattern(DEFAULT_HOP_CAP)
        # per-owned arms (the old-engine reachability path)
        per_owned: set[str] = set()
        for principal in owned:
            for arm in PER_OWNED_REACHABILITY_ARM_TEMPLATES:
                rows = port.graph.query(
                    arm.format(pattern=pattern), {"oid": principal}, timeout=60000
                ).result_set
                if rows:
                    per_owned.add(principal)
        # independent per-pair existence reference (both endpoints bound)
        probe = REACHABILITY_QUERY_TEMPLATE.format(pattern=pattern)
        per_pair: set[str] = set()
        for principal in owned:
            for jewel in jewels:
                rows = port.graph.query(
                    probe, {"oid": principal, "target": jewel}, timeout=30000
                ).result_set
                if rows and bool(rows[0][0]):
                    per_pair.add(principal)
                    break
        assert per_owned == per_pair, (
            f"per-owned arms {sorted(per_owned)} != per-pair reference {sorted(per_pair)}"
        )
        # and the port's own reachability agrees with both
        assert port.reachability() == len(per_pair)
    finally:
        # the sample fixture has no un-own path: cut the marker via raw Cypher
        port.graph.query(
            "MATCH (n {objectid: $o}) SET n.owned = false", {"o": some_user}
        )


@requires_engine
@requires_sample
def test_paths_to_jewels_equals_per_jewel_oracle(port):
    for oid in _legacy_owned(port):
        folded = port.paths_to_jewels(oid, DEFAULT_HOP_CAP)
        oracle = _legacy_paths(port, oid, DEFAULT_HOP_CAP)
        assert folded == oracle, f"folded path list for {oid} diverged from the per-jewel oracle"


@requires_engine
@requires_sample
def test_edge_frequency_equals_legacy_double_loop(port):
    freq = port.edge_frequency(DEFAULT_HOP_CAP)
    oracle: dict[tuple[str, str, str], int] = {}
    for oid in _legacy_owned(port):
        for path in _legacy_paths(port, oid, DEFAULT_HOP_CAP):
            for hop in path:
                oracle[hop] = oracle.get(hop, 0) + 1
    assert freq == oracle
    assert list(freq.items()) == list(oracle.items()), (
        "edge_frequency must be insertion-order identical too (replay-identical receipts)"
    )


@requires_engine
@requires_sample
def test_interdict_receipt_equals_independent_requery(port):
    from sever.core.scoring import interdict, snapshot

    top = max(port.edge_frequency(DEFAULT_HOP_CAP).items(), key=lambda kv: kv[1])[0]
    src, rel, dst = top
    receipt = interdict(port, src, dst, rel)
    after = snapshot(port, DEFAULT_HOP_CAP)
    assert receipt["after"] == after, "cut receipt must equal a fresh independent re-query"
    # restore the estate so the module's other equivalence reads stay stable
    port.add_edge(src, dst, rel)


@requires_engine
@requires_sample
def test_state_sequence_roundtrips(port):
    # THE TARGET PIN: the exact accessor sequence /api/state issues
    # (node count, edge count, jewels, owned, owned re-read, reachability)
    # costs <= 3 engine round-trips on the sample estate. Before audit7
    # this sequence was 11 sequential queries (measured: ryzen + Cloud).
    # The warmup pass below absorbs the one-time engine-version probe.
    port.reachability()
    port.rt_reset()
    port.node_count()
    port.edge_count()
    port.crown_jewels()
    port.owned_ids()
    port.owned_ids()
    port.reachability()
    rec = port.rt_receipt()
    assert rec["roundtrips"] <= 3, (
        f"/api/state accessor sequence cost {rec['roundtrips']} engine round-trips "
        f"(target <= 3): {rec['queries']}"
    )
    assert any("shortestPath" in q for q in rec["queries"]), (
        "reachability must still be MEASURED (never cached) — the arms must run"
    )


@requires_engine
@requires_sample
def test_api_state_response_equals_legacy_dict(monkeypatch):
    # identical API response: /api/state through the real handler returns
    # exactly the dict the legacy per-query forms produce
    import sever.console.app as appmod
    from fastapi.testclient import TestClient
    from sever.memory.flow import CaseLog

    graph = prefixed(f"{P}_api")
    monkeypatch.setenv("SEVER_FALKOR_GRAPH", graph)
    CaseLog(graph).path.unlink(missing_ok=True)
    api_port = make_live_port(graph)
    api_port.mark_owned(HERO)
    try:
        app = appmod.build_app(port=api_port)
        tc = TestClient(app)
        body = tc.get("/api/state").json()
        nodes, edges = _legacy_counts(api_port)
        assert body["nodes"] == nodes
        assert body["edges"] == edges
        assert body["jewels"] == _legacy_jewels(api_port)
        assert body["owned"] == _legacy_owned(api_port)
        assert body["reachability"] == api_port.reachability()
        assert body["backend"] == "falkordb"
        assert body["graph"] == graph
        # a second poll must be identical (steady-state cadence)
        second = tc.get("/api/state").json()
        assert second == body
    finally:
        drop_graph(api_port, graph)
        CaseLog(graph).path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Engine: invalidation — no accessor may ever serve a stale answer
# ---------------------------------------------------------------------------


@requires_engine
@requires_sample
def test_mutations_visible_immediately():
    name = prefixed(f"{P}_mut")
    port = make_live_port(name)
    try:
        some_user = sorted(port.user_objectids())[0]
        assert some_user not in port.owned_ids()
        port.node_count()  # populate the burst cache
        port.mark_owned(some_user)
        assert some_user in port.owned_ids(), "mark_owned must invalidate the owned cache"
        edges_before = port.edge_count()
        jewel = port.crown_jewels()[0]
        assert port.add_edge(some_user, jewel, "GENERIC_ALL") is True
        assert port.edge_count() == edges_before + 1, "add_edge must invalidate the counts"
        assert port.cut(some_user, jewel, "GENERIC_ALL") == 1
        assert port.edge_count() == edges_before, "cut must invalidate the counts"
        # out-of-band reset through the raw client (drop_graph's exact path)
        drop_graph(port, name)
        assert port.node_count() == 0, "a raw GRAPH.DELETE must never be served from cache"
    finally:
        drop_graph(port, name)


@requires_engine
@requires_sample
def test_raw_create_through_port_graph_invalidates():
    name = prefixed(f"{P}_rawcreate")
    port = make_live_port(name, load_sample=False)
    try:
        port.graph.query("CREATE (:User {objectid: 'u-a7', name: 'a7'})")
        assert port.node_count() == 1
        port.node_count()  # cache the 1-node estate
        # a raw write issued through port.graph (the way app code / fixtures
        # mutate outside the port methods) must drop the snapshot
        port.graph.query("CREATE (:User {objectid: 'u-b7', name: 'b7'})")
        assert port.node_count() == 2
    finally:
        drop_graph(port, name)


@requires_engine
@requires_sample
def test_scratch_copy_seeds_snapshot_and_is_isolated(port):
    scratch = port.scratch_copy(prefixed(f"{P}_scratch_once"))
    try:
        assert scratch._snapshot is not None, "copy+first-measure overlap must warm the copy"
        assert scratch.node_count() == port.node_count()
        assert scratch.owned_ids() == port.owned_ids()
        # isolation: mutating the scratch must not leak into the live estate
        live_edges_before = int(
            port.graph.query("MATCH ()-[r]->() RETURN count(r)").result_set[0][0]
        )
        scratch.cut("ghost-a7", "ghost-b7", "GENERIC_ALL")  # matches nothing: 0 removed
        assert int(
            port.graph.query("MATCH ()-[r]->() RETURN count(r)").result_set[0][0]
        ) == live_edges_before, "the live estate must be untouched by scratch mutations"
    finally:
        scratch.drop()
