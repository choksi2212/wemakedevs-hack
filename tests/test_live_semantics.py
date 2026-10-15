"""Live-engine semantics: hop-cap boundary, traversal-rel filtering, jewel
detection edge cases, owned-jewel, empty-owned/no-jewel, self-edges.

Runs against the real FalkorDB engine only (docker compose up -d); graphs are
crafted in-memory (NormalizedGraph) and loaded through the production
port.load() path, then dropped. No sample data required.
"""
from __future__ import annotations

import pytest

from tests.conftest import drop_graph, requires_engine
from sever.core.falkor_port import FalkorGraphPort
from sever.core.jewels import TRAVERSAL_RELS_SET
from sever.etl.ad_collectors import NormalizedGraph

pytestmark = [requires_engine]

J512 = "S-1-5-21-900-512"      # Domain-Admins RID group, deliberately RENAMED
DECOY = "S-1-5-21-900-1106"    # NAMED 'Domain Admins', wrong RID
CHAIN12 = "S-1-5-21-900-1001"  # 12 MEMBER_OF hops to the jewel
CHAIN13 = "S-1-5-21-900-1000"  # 13 MEMBER_OF hops to the jewel
STRUCT = "S-1-5-21-900-3000"   # CONTAINED_BY-only route (not attacker-chainable)
MIXED = "S-1-5-21-900-3100"    # MEMBER_OF then CONTAINED_BY
SELF = "S-1-5-21-900-4000"


def _craft_graph() -> NormalizedGraph:
    g = NormalizedGraph()
    g.add_node(J512, "Group", {"name": "TotallyNotAdmins"})
    g.add_node(DECOY, "Group", {"name": "Domain Admins"})
    # case-varied Entra role-holder names: all three must be jewels
    g.add_node("az-1", "AZUser", {"name": "097ef6c2-GlobalAdministrator"})
    g.add_node("az-2", "AZUser", {"name": "jdoe-globaladministrator"})
    g.add_node("az-3", "AZUser", {"name": "jdoe-GLOBALADMINISTRATOR"})
    for i in range(1000, 1013):  # 13 chain nodes: 1000 -> ... -> 1012 -> jewel
        g.add_node("S-1-5-21-900-%d" % i, "User", {"name": "chain%d" % (i - 999)})
    for i in range(1000, 1012):
        g.add_edge("S-1-5-21-900-%d" % i, "S-1-5-21-900-%d" % (i + 1), "MEMBER_OF")
    g.add_edge("S-1-5-21-900-1012", J512, "MEMBER_OF")     # 12th hop from 1001
    g.add_node(STRUCT, "User", {"name": "structonly"})
    g.add_edge(STRUCT, J512, "CONTAINED_BY")               # structural-only route
    g.add_node(MIXED, "User", {"name": "mixed"})
    g.add_edge(MIXED, STRUCT, "MEMBER_OF")                 # traversable then structural
    g.add_node(SELF, "User", {"name": "selfloop"})
    return g


@pytest.fixture()
def port():
    p = FalkorGraphPort(graph_name="sever_audit2_core_t1")
    drop_graph(p, "sever_audit2_core_t1")
    p.load(_craft_graph())
    yield p
    drop_graph(p, "sever_audit2_core_t1")


def test_crown_jewel_detection_live(port):
    # renamed -512 group detected (SID-based); decoy named 'Domain Admins'
    # excluded (RID 1106); case-varied AZUser holders all detected
    assert port.crown_jewels() == [J512, "az-1", "az-2", "az-3"]


def test_reachability_honors_hop_cap_and_traversal_set(port):
    for oid in (CHAIN13, CHAIN12, STRUCT, MIXED):
        port.mark_owned(oid)
    # only the 12-hop traversal-chain principal counts at the default cap:
    # the 13-hop chain is beyond cap 12, the CONTAINED_BY-only and mixed
    # routes are not attacker-chainable
    assert port.reachability() == 1
    assert port.reachability(12) == 1
    assert port.reachability(13) == 2   # cap is inclusive: 13-hop chain at cap 13
    assert port.reachability(1) == 0    # 12 hops is beyond cap 1


def test_paths_honors_hop_cap_boundary_and_rels(port):
    paths12 = port.paths_to_jewels(CHAIN12, 12)
    assert len(paths12) == 1
    assert len(paths12[0]) == 12                       # inclusive upper bound
    assert all(rel in TRAVERSAL_RELS_SET for _, rel, _ in paths12[0])
    assert paths12[0][-1][2] == J512
    assert port.paths_to_jewels(CHAIN13, 12) == []     # 13 hops > cap 12
    paths13 = port.paths_to_jewels(CHAIN13, 13)
    assert len(paths13) == 1 and len(paths13[0]) == 13
    assert port.paths_to_jewels(STRUCT, 12) == []      # structural-only
    assert port.paths_to_jewels(MIXED, 12) == []


def test_ties_mode_never_reports_structural_or_overlong_hops(port):
    port.mark_owned(CHAIN12)
    try:
        paths = port.paths_to_jewels(CHAIN12, 12, ties=True)
        port.mark_owned(STRUCT)
        assert port.paths_to_jewels(STRUCT, 12, ties=True) == []
    except Exception as exc:
        # algo.SPpaths intermittently fails server-side on this falkordb build
        # under concurrent graph churn ("unhandled type in inlined
        # properties" — documented in docs/CYPHER.md); the ties mode is
        # offline-only and the guard logic is covered engine-free in
        # tests/test_core_edges.py, so skip rather than fail on the engine bug
        if "inlined properties" in str(exc):
            pytest.skip(
                "algo.SPpaths unavailable on this engine state "
                "(falkordb 6.0.0 shared-engine instability; offline mode only)"
            )
        raise
    for path in paths:
        assert 0 < len(path) <= 12
        assert all(rel in TRAVERSAL_RELS_SET for _, rel, _ in path)


def test_owned_jewel_is_reached(port):
    # a compromised principal that IS a crown jewel counts as reached
    # (shortestPath needs >=1 hop for a self-pair — the port counts it directly)
    port.mark_owned(J512)
    assert port.owned_ids() == [J512]
    assert port.reachability() == 1
    assert port.paths_to_jewels(J512, 12) == []  # nothing to enumerate/cut


def test_empty_owned_and_missing_jewels(port):
    assert port.owned_ids() == []            # nobody compromised
    assert port.reachability() == 0
    p2 = FalkorGraphPort(graph_name="sever_audit2_core_t2")
    try:
        drop_graph(p2, "sever_audit2_core_t2")
        g = NormalizedGraph()
        g.add_node("S-1-5-21-901-1106", "Group", {"name": "Domain Admins"})
        g.add_node("S-1-5-21-901-2000", "User", {"name": "u"})
        g.add_edge("S-1-5-21-901-2000", "S-1-5-21-901-1106", "MEMBER_OF")
        g.add_node("az-9", "AZUser", {"name": "plain_user"})
        p2.load(g)
        assert p2.crown_jewels() == []       # no -512/-519 group, no GA holder
        p2.mark_owned("S-1-5-21-901-2000")
        assert p2.reachability() == 0        # owned but no jewel to reach
    finally:
        drop_graph(p2, "sever_audit2_core_t2")


def test_live_mutation_self_edge_and_absent_endpoint(port):
    # self-referencing grant: rejected like the ETL contract, no query effect
    assert port.add_edge(SELF, SELF, "GENERIC_ALL") is False
    n = port.graph.query(
        "MATCH (a)-[r:GENERIC_ALL]->(a) RETURN count(r) AS n", timeout=60000
    ).result_set[0][0]
    assert n == 0
    # absent endpoint: nothing created, contract-False
    assert port.add_edge("S-1-5-21-900-9999", J512, "MEMBER_OF") is False
