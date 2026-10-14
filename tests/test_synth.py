"""Synthetic tenant generator tests — uniqueness, structure, crown jewels."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from sever.etl.ad_collectors import parse_ad_dir
from sever.synth.tenants import make_tenant, tenant_graph_name

SAMPLE_DIR = os.environ.get("SEVER_SAMPLE_DIR", "N:/HERMESSSS/graphhacks/data/ad_sample")
pytestmark = pytest.mark.skipif(
    not Path(SAMPLE_DIR).is_dir(), reason=f"sample data not present at {SAMPLE_DIR}"
)


@pytest.fixture(scope="module")
def base():
    return parse_ad_dir(SAMPLE_DIR)


def test_tenant_preserves_structure(base):
    t1 = make_tenant(base, 1)
    assert t1.stats["node_count"] == base.stats["node_count"]
    assert t1.stats["edge_count"] == base.stats["edge_count"]
    lc1 = {}
    for n in t1.nodes.values():
        lc1[n["label"]] = lc1.get(n["label"], 0) + 1
    assert lc1.get("User") == base.stats["label_counts"]["User"]


def test_tenants_have_disjoint_identities(base):
    t1, t2 = make_tenant(base, 1), make_tenant(base, 2)
    assert not (set(t1.nodes) & set(t2.nodes)), "tenant graphs must share zero objectids"


def test_deterministic_regeneration(base):
    t1a, t1b = make_tenant(base, 1), make_tenant(base, 1)
    assert list(t1a.nodes) == list(t1b.nodes)
    assert t1a.edges.keys() == t1b.edges.keys()


def test_crown_jewels_survive_remap(base):
    t1 = make_tenant(base, 1)
    jewels = [n for n in t1.nodes.values() if n["label"] == "Group" and n["objectid"].endswith(("-512", "-519"))]
    assert len(jewels) == 5  # same crown-jewel count as base (DA x3 + EA x2)


def test_tenant_graph_names():
    assert tenant_graph_name(1) == "sever_tenant001"
    assert tenant_graph_name(300) == "sever_tenant300"


def test_names_carry_tenant_marker(base):
    t1 = make_tenant(base, 1)
    names = [n["props"].get("name", "") for n in t1.nodes.values() if n["label"] == "User"]
    assert any("T001" in n or ".T001" in n for n in names)
