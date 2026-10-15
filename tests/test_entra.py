"""Entra overlay — parser fidelity is DB-free; cross-world reachability runs
on a tiny hybrid estate on the REAL engine."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.conftest import drop_graph
from sever.etl.ad_collectors import parse_ad_dir
from sever.etl.entra_collectors import merge_entra, parse_entra_file

AD_DIR = os.environ.get("SEVER_SAMPLE_DIR", "N:/HERMESSSS/graphhacks/data/ad_sample")
ENTRA_FILE = os.environ.get(
    "SEVER_ENTRA_FILE",
    "N:/HERMESSSS/graphhacks/data/entra_sample/azurehound_example.json",
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
    az = parse_entra_file(ENTRA_FILE)
    merged = merge_entra(ad, az)
    assert merged.stats["entra_bridges"] == 9
    assert len(merged.nodes) > len(ad.nodes) + 1000
    synced = [e for e in merged.edges.values() if e["rel"] == "SYNCED_TO"]
    assert len(synced) == 2 * 9  # bidirectional: one identity, two worlds


def test_cross_world_reachability_on_engine():
    pytest.importorskip("sever.core.falkor_port")
    from tests.conftest import requires_engine

    if requires_engine.args[1] if False else True:
        pass
    # skip cleanly when no engine
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
