"""DB-free guards: Cypher injection protection + query-shape contracts."""
from __future__ import annotations

import pytest

from sever.core.falkor_port import (
    AZ_JEWELS_QUERY,
    CUT_ATOMIC_QUERY_TEMPLATE,
    ESTATE_SNAPSHOT_QUERY,
    JEWELS_QUERY,
    MARK_OWNED_QUERY,
    PATH_QUERY_TEMPLATE,
    REACHABILITY_METHOD,
    REACHABILITY_QUERY_TEMPLATE,
    FalkorGraphPort,
)
from sever.core.jewels import TRAVERSAL_RELS, cypher_traversal_pattern


def test_query_constants_shape():
    pattern = cypher_traversal_pattern(12)
    assert "MEMBER_OF" in pattern and "GENERIC_ALL" in pattern and "*..12" in pattern
    assert "shortestPath" in REACHABILITY_METHOD  # the shipped method names its shortestPath forms
    reach_q = REACHABILITY_QUERY_TEMPLATE.format(pattern=pattern)
    assert reach_q.startswith("MATCH (o {objectid: $oid})")
    assert "WITH shortestPath((o)-" in reach_q and "->(t)) AS p" in reach_q
    assert "RETURN p IS NOT NULL AS hit" in reach_q
    assert "$oid" in reach_q and "$target" in reach_q
    path_q = PATH_QUERY_TEMPLATE.format()
    # the ties-mode template has NO pattern slot: it carries the traversal
    # vocabulary inline via relTypes (audit N38: the old .format(pattern=)
    # passed a kwarg no slot consumed — silently misleading)
    assert "{pattern}" not in PATH_QUERY_TEMPLATE
    assert path_q.startswith("MATCH (o {objectid: $oid})")
    assert "algo.SPpaths" in path_q and "pathCount: 100" in path_q
    assert "relTypes" in path_q  # ties mode: traversal set enforced server-side
    assert all(f"'{rel}'" in path_q for rel in TRAVERSAL_RELS)
    assert "$oid" in path_q and "$target" in path_q
    cut_q = CUT_ATOMIC_QUERY_TEMPLATE.format(rel="GENERIC_ALL")
    assert "$src" in cut_q and "$dst" in cut_q
    assert "DELETE r" in cut_q and "RETURN count(r)" in cut_q
    assert cut_q.count("MATCH") == 1  # atomic: no separate pre-count read
    assert "SET n.owned = true" in MARK_OWNED_QUERY
    assert "ENDS WITH" in JEWELS_QUERY and "ENDS WITH" in AZ_JEWELS_QUERY
    # AZ holders are collector data: the suffix match must be case-insensitive
    assert "toLower" in AZ_JEWELS_QUERY


class _RecordingClient:
    """Stand-in for the falkordb-py graph object (wire-shape unit tests)."""

    def __init__(self, results=None):
        from collections import deque

        self.calls: list[tuple[str, dict | None]] = []
        self._results = deque(results or [])

    def query(self, query, params=None, timeout=None):
        self.calls.append((query, params))

        class _R:
            result_set = [self._results.popleft()] if self._results else [[0]]

        return _R()


def test_falkor_cut_is_one_atomic_delete_and_count_statement():
    rec = _RecordingClient(results=[[1]])  # the atomic statement returns the removed count: 1
    port = FalkorGraphPort(client=rec)
    deleted = port.cut("S-src", "S-dst", "GENERIC_ALL")
    assert deleted == 1
    queries = [q for q, _ in rec.calls]
    assert any("count(r)" in q for q in queries)
    assert any("DELETE r" in q for q in queries)
    assert all((p or {}).get("src") == "S-src" and (p or {}).get("dst") == "S-dst" for _, p in rec.calls)


def test_cypher_injection_guard():
    port = FalkorGraphPort(client=_RecordingClient())
    for evil in (
        "GENERIC_ALL}) DETACH DELETE (n) //",
        "a-b-c",
        "x' OR '1'='1",
        "",
        "A}) DETACH",
        "MATCH (x) DETACH DELETE (x)",
        "A B",
        # --- test-gaps audit: more payloads ---
        "generic_all",                 # lowercase violates the rel schema
        "GenericAll",
        " GENERIC_ALL",                # surrounding whitespace
        "GENERIC_ALL ",
        "A\nB",                        # embedded control characters
        "A\tB",
        "A\rB",
        "A\x00B",                      # NUL byte
        "`MATCH`",                     # backtick escape
        "A\\",                         # trailing backslash
        "GENERIC-ALL",                 # hyphen
        "9ABC",                        # must start with a letter
        "_ABC",
        "GENERIC_ÄLL",                 # non-ASCII never matches [A-Z]
        "A' OR '1'='1",
        "A" * 65,                      # over the 64-char schema bound
    ):
        with pytest.raises(ValueError):
            port.add_edge("A", "B", evil)
        with pytest.raises(ValueError):
            port.cut("A", "B", evil)
    # non-string rels are rejected before interpolation too, whatever the flavor
    with pytest.raises((ValueError, TypeError)):
        port.add_edge("A", "B", None)
    with pytest.raises((ValueError, TypeError)):
        port.cut("A", "B", b"GENERIC_ALL")
    # valid vocabulary passes the guard
    port.add_edge("A", "B", "GENERIC_ALL")
    port.cut("A", "B", "MEMBER_OF")


def test_rel_schema_boundaries():
    # closed vocabulary: only rels the ETL emits / the engine chains are valid;
    # arbitrary identifier-shaped strings ("A", "X_9", "generic_all") reject
    port = FalkorGraphPort(client=_RecordingClient(results=[[0]] * 5))
    for good in ("GENERIC_ALL", "MEMBER_OF", "READ_GMSAPASSWORD", "AZOwns", "DCSYNC"):
        assert port.add_edge("S-src", "S-dst", good) is True
    assert len(port.graph.calls) == 5  # ONE atomic query per rel (pre-count + MERGE)
    for q, _ in port.graph.calls:
        assert "OPTIONAL MATCH" in q and "MERGE" in q and "RETURN pre" in q
    for bad in ("A", "X_9", "A" * 64, "generic_all", "GENERIC_ALL}) DETACH DELETE (n) //"):
        with pytest.raises(ValueError):
            port.add_edge("S-src", "S-dst", bad)


def test_add_edge_wire_shape_and_idempotent_false():
    # atomic idempotency: a single query returns the pre-MERGE edge count;
    # pre == 0 -> created (True), pre == 1 -> already existed (False)
    rec = _RecordingClient(results=[[0]])
    port = FalkorGraphPort(client=rec)
    assert port.add_edge("S-src", "S-dst", "GENERIC_ALL", {"source": "F-9"}) is True
    q, params = rec.calls[0]
    assert "OPTIONAL MATCH (s)-[r0:GENERIC_ALL]->(t)" in q
    assert "MERGE (s)-[r:GENERIC_ALL]->(t)" in q
    assert "SET r += $props" in q
    assert "RETURN pre" in q
    assert params == {"src": "S-src", "dst": "S-dst", "props": {"source": "F-9"}}
    rec2 = _RecordingClient(results=[[1]])
    port2 = FalkorGraphPort(client=rec2)
    assert port2.add_edge("S-src", "S-dst", "GENERIC_ALL") is False
    assert len(rec2.calls) == 1


def test_cut_is_one_atomic_statement_even_for_zero_edges():
    # audit5/multi-client: the count-then-delete pair (which skipped the
    # DELETE when the count read 0) is gone — cut is now ONE engine-side
    # delete-and-count statement, atomic per command, so a zero-match cut
    # still costs exactly one call, returns 0, and cannot race a concurrent
    # cutter into a phantom double-claim.
    rec = _RecordingClient(results=[[0]])
    port = FalkorGraphPort(client=rec)
    assert port.cut("A", "B", "GENERIC_ALL") == 0
    assert len(rec.calls) == 1                    # one atomic statement — never two
    assert "DELETE r" in rec.calls[0][0]
    assert "RETURN count(r)" in rec.calls[0][0]


# ---- reachability (wire-shape, DB-free; audit C1): the PER-PAIR EXISTENCE
# LOOP is what every unvouched port takes (pre-6.0.0 engines, failed probes,
# folds-off stubs) — pinned here on a probe-less stub; the modern two-arm
# all-pairs form is pinned via a vouched stub (canned MODULE LIST). Covers
# hop-cap binding, first-hit counting, union semantics, the owned-jewel
# breach case and the empty-jewel case (audit3/test-forensics: mutations
# M9/M11/M1 on reachability were invisible to every engine-free test
# before this)


class _SequenceGraph:
    """Serves canned result rows in call order."""

    def __init__(self, results):
        from collections import deque

        self.calls: list[tuple[str, object]] = []
        self._results = deque(results)

    def query(self, query, params=None, timeout=None):
        self.calls.append((query, params))

        class _R:
            result_set = self._results.popleft() if self._results else []

        return _R()


def test_reachability_unvouched_port_runs_per_pair_existence_loop():
    # the classic wire-shape stubs have no .client -> the version probe
    # fails -> the port is UNVOUCHED (audit C1): reachability must issue the
    # per-pair existence probe (REACHABILITY_QUERY_TEMPLATE, both endpoints
    # $param-bound) and never the cross-product arm forms
    results = [
        [["j-512"]],      # crown_jewels(): JEWELS_QUERY
        [["az-ga"]],      # crown_jewels(): AZ_JEWELS_QUERY
        [["o1"], ["o2"]], # owned_ids()
        [[1]],            # o1 x az-ga (jewels sorted): FIRST-HIT -> break
        [[0]], [[0]],     # o2 x az-ga, o2 x j-512: never reaches
    ]
    rec = _SequenceGraph(results)
    port = FalkorGraphPort(client=rec)
    assert port.reachability(hop_cap=5) == 1  # only the reacher counts
    probe_calls = [(q, p) for q, p in rec.calls if "shortestPath" in q]
    assert len(probe_calls) == 3, "first hit must stop the probe fan-out"
    probe_q, probe_params = probe_calls[0]
    assert probe_q.startswith("MATCH (o {objectid: $oid}), (t {objectid: $target})")
    assert "WITH shortestPath((o)-" in probe_q and "RETURN p IS NOT NULL AS hit" in probe_q
    # the CALLER's hop cap is bound into the per-pair pattern (mutation M9)
    assert "*..5" in probe_q
    # both endpoints are $param-bound on every probe — never interpolated
    assert all(p and set(p) == {"oid", "target"} for _, p in probe_calls)
    # and the cross-product arm forms are never issued on an unvouched port
    assert not any("MATCH (o {owned: true})," in q for q, _ in rec.calls), (
        "unvouched ports must not run the all-owned arm forms (audit C1: the "
        "form undercounts with >= 2 owned principals on Cloud 4.22.0)"
    )


def test_reachability_owned_jewel_counts_directly_without_probes():
    # owned-jewel breach case (mutation M1): an owned crown jewel counts
    # directly (0-hop breach shortestPath cannot see), issuing ZERO probes
    rec = _SequenceGraph([
        [["S-jewel-g"]], [],      # crown jewels: one AD jewel
        [["S-jewel-g"]],          # owned: the jewel itself
    ])
    port = FalkorGraphPort(client=rec)
    assert port.reachability() == 1
    assert not any("shortestPath" in q for q, _ in rec.calls), (
        "an owned crown jewel is counted directly — no probe fan-out"
    )


def test_reachability_empty_jewels_is_zero_without_probes():
    rec = _SequenceGraph([
        [], [],      # no AD jewels, no AZ jewels
        [["o1"]],    # one owned principal
    ])
    port = FalkorGraphPort(client=rec)
    assert port.reachability() == 0
    assert not any("shortestPath" in q for q, _ in rec.calls)


class _VouchedGraph:
    """Stub WITH a ``.client`` whose MODULE LIST answers falkordb 6.0.0 —
    the port treats it as a vouched real client, so reachability() takes
    the modern CONCURRENT-ARMS path DB-free. Answers by QUERY TEXT, not
    call order (the two arms run on pool threads)."""

    def __init__(self, arm_group_rows, arm_az_rows, owned, ad, az, nodes=7, edges=9):
        self.client = type(
            "_C", (), {"execute_command": lambda self, *a, **k: [["name", "graph", "ver", 60000]]}
        )()
        self.calls: list[str] = []
        self._arm_group_rows = arm_group_rows
        self._arm_az_rows = arm_az_rows
        self._estate = (owned, ad, az, nodes, edges)

    def query(self, query, params=None, timeout=None):
        self.calls.append(query)
        if query == ESTATE_SNAPSHOT_QUERY:
            class _Snap:
                result_set = [[list(self._estate[0]), list(self._estate[1]),
                               list(self._estate[2]), self._estate[3], self._estate[4]]]
            return _Snap()
        if "shortestPath" in query:
            class _Rows:
                result_set = self._arm_az_rows if "AZUser" in query else self._arm_group_rows
            return _Rows()
        class _Empty:
            result_set = []
        return _Empty()


def test_reachability_vouched_port_runs_both_arms_with_hop_cap_binding():
    g = _VouchedGraph(
        arm_group_rows=[["arm1-oid"]], arm_az_rows=[["arm2-oid"]],
        owned=["o1"], ad=["j-512"], az=["az-ga"],
    )
    port = FalkorGraphPort(client=g)
    assert port._modern_engine is True
    assert port.reachability(hop_cap=5) == 2  # UNION of both arms, deduped
    arm_queries = [q for q in g.calls if "shortestPath" in q]
    assert len(arm_queries) == 2, "both arms must be issued"
    group_arm, az_arm = arm_queries
    assert "Group" in group_arm and "AZUser" not in group_arm
    assert "AZUser" in az_arm and "toLower(t.name) ENDS WITH '-globaladministrator'" in az_arm
    # the CALLER's hop cap is bound into BOTH arm patterns (mutation M9)
    assert "*..5" in group_arm and "*..5" in az_arm
    # the arms + the snapshot are the whole poll — no per-pair fan-out
    assert not any(q.startswith("MATCH (o {objectid: $oid}), (t {objectid: $target})")
                   for q in g.calls)
    # snapshot-served owned-jewel breach (mutation M1): the estate's own
    # jewel in the owned set counts directly alongside the arms' answers
    g2 = _VouchedGraph(
        arm_group_rows=[], arm_az_rows=[],
        owned=["az-ga"], ad=["j-512"], az=["az-ga"],
    )
    port2 = FalkorGraphPort(client=g2)
    assert port2.reachability() == 1
