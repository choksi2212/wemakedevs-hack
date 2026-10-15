"""Entra overlay — parser fidelity is DB-free; cross-world reachability runs
on a tiny hybrid estate on the REAL engine."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tests.conftest import drop_graph
from sever.etl.ad_collectors import parse_ad_dir
from sever.etl.entra_collectors import merge_entra, parse_entra_file

_REPO_ROOT = Path(__file__).resolve().parents[1]
AD_DIR = os.environ.get(
    "SEVER_SAMPLE_DIR", str(_REPO_ROOT / "data" / "ad_sample"))
ENTRA_FILE = os.environ.get(
    "SEVER_ENTRA_FILE",
    str(_REPO_ROOT / "data" / "entra_sample" / "azurehound_example.json"),
)
pytestmark = pytest.mark.skipif(
    not (Path(AD_DIR).is_dir() and Path(ENTRA_FILE).is_file()),
    reason="sample data not present",
)


def test_entra_parse_counts():
    az = parse_entra_file(ENTRA_FILE)
    assert az.stats["records"] == 29800
    assert len(az.nodes) > 12000
    assert len(az.edges) > 12000
    labels = {n["label"] for n in az.nodes.values()}
    assert {"AZUser", "AZServicePrincipal", "AZApp", "AZTenant"} <= labels


def test_entra_ga_holder_present():
    az = parse_entra_file(ENTRA_FILE)
    ga = [n for n in az.nodes.values()
          if n["label"] == "AZUser" and n["props"].get("name", "").endswith("-GlobalAdministrator")]
    assert len(ga) == 1


def test_merged_graph_bridges():
    ad = parse_ad_dir(AD_DIR)
    base_nodes = len(ad.nodes)  # merge_entra merges IN PLACE into `ad`
    az = parse_entra_file(ENTRA_FILE)
    merged = merge_entra(ad, az)
    assert merged.stats["entra_bridges"] == 9
    assert len(merged.nodes) > base_nodes + 1000
    synced = [e for e in merged.edges.values() if e["rel"] == "SYNCED_TO"]
    assert len(synced) == 2 * 9  # bidirectional: one identity, two worlds


def test_entra_vm_role_edges_present():
    """Audit fix: the extractor specs previously read principalId/vmId fields
    that do not exist in the sample — zero VM/RG/MG/Sub/KV role edges were
    derived. The real shape is <roleKey>s lists + virtualMachineId etc."""
    az = parse_entra_file(ENTRA_FILE)
    rels = {e["rel"] for e in az.edges.values()}
    for rel in (
        "AZVMAdminLogin",
        "AZVMContributor",
        "AZVMUserAccessAdmin",
        "AZVMAvereContributor",
        "AZRGUserAccessAdmin",
        "AZSubUserAccessAdmin",
        "AZMGUserAccessAdmin",
        "AZKVUserAccessAdmin",
        "AZKVContributor",
    ):
        assert rel in rels, f"{rel} edges missing"


def test_entra_every_edge_endpoint_resolves():
    """ARM roleAssignment entries nest the principal under
    properties.principalId (the entry's own id is the roleAssignment path);
    AZAppOwner references apps by client-id appId while AZApp nodes are keyed
    by object id. Both previously produced dangling endpoints that silently
    vanished at Cypher load (edge batches MATCH both endpoints)."""
    az = parse_entra_file(ENTRA_FILE)
    ids = set(az.nodes)
    dangling = [e for e in az.edges.values() if e["src"] not in ids or e["dst"] not in ids]
    assert dangling == [], f"{len(dangling)} dangling entra edges, e.g. {dangling[:3]}"


def test_entra_app_owner_edges_target_app_object_ids():
    az = parse_entra_file(ENTRA_FILE)
    app_ids = {n for n, nd in az.nodes.items() if nd["label"] == "AZApp"}
    owns = [e for e in az.edges.values() if e["props"].get("source_kind") == "AZAppOwner"]
    assert owns, "no AZAppOwner edges"
    assert all(e["dst"] in app_ids for e in owns)


def test_entra_arm_role_principals_resolved_not_roleassignment_paths():
    """Every ARM role edge src must be a principal object id, never a
    "/providers/Microsoft.Authorization/roleAssignments/..." path."""
    az = parse_entra_file(ENTRA_FILE)
    bad = [
        e for e in az.edges.values()
        if "roleAssignments/" in e["src"] or "roleAssignments/" in e["dst"]
    ]
    assert bad == []


def test_entra_unresolved_nodes_are_flagged():
    """Referenced-but-uncollected principals (AzureHound inlines the object
    in owners/members entries) are materialized honestly with the unresolved
    flag — same contract as the AD parser."""
    az = parse_entra_file(ENTRA_FILE)
    unres = [n for n in az.nodes.values() if n["props"].get("unresolved")]
    assert len(unres) > 100
    assert all(n["label"].startswith("AZ") for n in unres)


def test_entra_parse_is_deterministic_edge_set_hash():
    import hashlib

    def edge_hash(g):
        payload = sorted(
            (e["src"], e["dst"], e["rel"], json.dumps(e["props"], sort_keys=True, default=str))
            for e in g.edges.values()
        )
        return hashlib.sha256(json.dumps(payload).encode()).hexdigest()

    g1 = parse_entra_file(ENTRA_FILE)
    g2 = parse_entra_file(ENTRA_FILE)
    assert edge_hash(g1) == edge_hash(g2)


def test_cross_world_reachability_on_engine():
    # skip cleanly when no engine (the module pytestmark only gates on sample
    # presence, so the engine check lives in the try/except below). The old
    # head of this test was dead weight: a no-op importorskip of a module
    # that imports fine without the engine, an unused requires_engine import,
    # and an `if <always-True>: pass` tautology branch (audit3/test-forensics).
    try:
        from sever.core.falkor_port import FalkorGraphPort
        name = "sever_test_entra_tiny"
        port = FalkorGraphPort(graph_name=name)
        port.node_count()
    except Exception:
        pytest.skip("requires the live FalkorDB engine")
    try:
        drop_graph(port, name)
        # tiny hybrid estate: on-prem ANDY -> synced AZ identity; cloud-compromise
        # pivots the bridge into on-prem Domain Admins
        port.graph.query(
            "CREATE (u:User {objectid: 'S-1-5-21-t-2187', name: 'andy', owned: false}), "
            "(d:Group {objectid: 'S-1-5-21-t-512', name: 'domain admins'}), "
            "(az:AZUser {objectid: 'az-andy', name: 'andy@cloud', owned: false})",
        )
        port.graph.query(
            "MATCH (u:User {objectid: 'S-1-5-21-t-2187'}), (d:Group {objectid: 'S-1-5-21-t-512'}) "
            "CREATE (u)-[:MEMBER_OF]->(d)",
        )
        port.graph.query(
            "MATCH (u:User {objectid: 'S-1-5-21-t-2187'}), (az:AZUser {objectid: 'az-andy'}) "
            "CREATE (u)-[:SYNCED_TO]->(az)",
        )
        port.graph.query(
            "MATCH (u:User {objectid: 'S-1-5-21-t-2187'}), (az:AZUser {objectid: 'az-andy'}) "
            "CREATE (az)-[:SYNCED_TO]->(u)",
        )
        from sever.core.jewels import is_crown_jewel
        assert is_crown_jewel("S-1-5-21-t-512", "Group")
        port.mark_owned("az-andy")
        assert port.reachability() == 1  # cloud identity pivots into on-prem DA
        assert port.cut("az-andy", "S-1-5-21-t-2187", "SYNCED_TO") >= 1
        assert port.reachability() == 0  # bridge severed -> collapse
    finally:
        drop_graph(port, name)
