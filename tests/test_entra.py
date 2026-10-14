"""Entra overlay tests — parser fidelity, bridges, hybrid jewels, cross-world reach."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from sever.core.mock_port import MockGraphPort
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


@pytest.fixture()
def ad():
    return parse_ad_dir(AD_DIR)


@pytest.fixture()
def az():
    return parse_entra_file(ENTRA_FILE)


def test_entra_parse_counts(az):
    assert az.stats["records"] == 29800
    assert len(az.nodes) > 12000        # ~12.9K AZ nodes
    assert len(az.edges) > 12000       # AZOwns/AZMemberOf/AZAppRole
    labels = {n["label"] for n in az.nodes.values()}
    assert {"AZUser", "AZServicePrincipal", "AZApp", "AZTenant"} <= labels


def test_entra_ga_holder_present(az):
    ga = [n for n in az.nodes.values()
          if n["label"] == "AZUser" and n["props"].get("name", "").endswith("-GlobalAdministrator")]
    assert len(ga) == 1


def test_merged_graph(ad, az):
    pre_nodes = len(ad.nodes)
    merged = merge_entra(ad, az)
    assert merged.stats["entra_bridges"] == 9
    assert len(merged.nodes) > pre_nodes + 1000
    # bidirectional bridges: every SYNCED_TO pair exists in both directions
    synced = [e for e in merged.edges.values() if e["rel"] == "SYNCED_TO"]
    assert len(synced) == 2 * 9


def test_hybrid_jewels_and_cross_world_reach(ad, az):
    merged = merge_entra(ad, az)
    port = MockGraphPort()
    port.load(merged)
    jewels = port.crown_jewels()
    assert len(jewels) == 6  # 5 AD groups + 1 AZUser GA holder
    # THE HYBRID STORY: compromise the cloud identity of synced user ANDY
    # -> reverse SYNCED_TO bridge -> on-prem chains -> Domain Admins
    AZ_ANDY = "3892f15b-2264-4927-8366-74b0f7f49761"
    assert AZ_ANDY in port.g.nodes
    port.mark_owned(AZ_ANDY)
    assert port.reachability() == 1
    paths = port.paths_to_jewels(AZ_ANDY)
    assert paths, "cloud identity must reach AD crown jewels via the reverse bridge"
    assert any(hop[1] == "SYNCED_TO" for path in paths for hop in path)
    # and the interdiction still works cross-world: cut the bridge
    AZ_ANDY_AD = "S-1-5-21-2697957641-2271029196-387917394-2187"
    assert port.cut(AZ_ANDY, AZ_ANDY_AD, "SYNCED_TO") >= 1
    assert port.reachability() == 0
