"""Synthetic tenant generator tests — uniqueness, structure, crown jewels.
Estate-wide assertions run against the CE sample when present; identity-remap
edge cases run on tiny synthetic bases (DB-free, sample-free)."""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from tests.conftest import requires_sample
from sever.etl.ad_collectors import NormalizedGraph, parse_ad_dir
from sever.synth.tenants import _remap_guid, _remap_sid, make_tenant, tenant_graph_name

SAMPLE_DIR = os.environ.get(
    "SEVER_SAMPLE_DIR",
    str(Path(__file__).resolve().parents[1] / "data" / "ad_sample"),
)
pytestmark = pytest.mark.skipif(
    not Path(SAMPLE_DIR).is_dir(), reason=f"sample data not present at {SAMPLE_DIR}"
)

GUID = "C4A66CF4-0FEA-44FA-B65E-6553F7C3BDD4"
_GUID_RE = re.compile(r"^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$")


@pytest.fixture(scope="module")
def base():
    return parse_ad_dir(SAMPLE_DIR)


# ---- on the sample estate (each test skips when the sample is absent) ----


@requires_sample
def test_tenant_preserves_structure(base):
    t1 = make_tenant(base, 1)
    assert t1.stats["node_count"] == base.stats["node_count"]
    assert t1.stats["edge_count"] == base.stats["edge_count"]
    lc1 = {}
    for n in t1.nodes.values():
        lc1[n["label"]] = lc1.get(n["label"], 0) + 1
    assert lc1.get("User") == base.stats["label_counts"]["User"]


@requires_sample
def test_tenants_have_disjoint_identities(base):
    t1, t2 = make_tenant(base, 1), make_tenant(base, 2)
    assert not (set(t1.nodes) & set(t2.nodes)), "tenant graphs must share zero objectids"


@requires_sample
def test_deterministic_regeneration(base):
    t1a, t1b = make_tenant(base, 1), make_tenant(base, 1)
    assert list(t1a.nodes) == list(t1b.nodes)
    assert t1a.edges.keys() == t1b.edges.keys()


@requires_sample
def test_crown_jewels_survive_remap(base):
    t1 = make_tenant(base, 1)
    jewels = [n for n in t1.nodes.values() if n["label"] == "Group" and n["objectid"].endswith(("-512", "-519"))]
    assert len(jewels) == 5  # same crown-jewel count as base (DA x3 + EA x2)


@requires_sample
def test_names_carry_tenant_marker(base):
    t1 = make_tenant(base, 1)
    names = [n["props"].get("name", "") for n in t1.nodes.values() if n["label"] == "User"]
    assert any("T001" in n or ".T001" in n for n in names)


# ---- identity remapping edge cases (DB-free, sample-free) ----


def test_tenant_graph_names():
    assert tenant_graph_name(1) == "sever_tenant001"
    assert tenant_graph_name(300) == "sever_tenant300"


def test_remap_guid_leaves_non_guid_strings_untouched():
    for oid in (
        "not-a-guid",
        "",
        "S-1-5-21-2697957641-2271029196-387917394-512",  # SIDs are not GUIDs
        "C4A66CF4-0FEA-44FA-B65E",                         # too few groups
        "C4A66CF4-0FEA-44FA-B65E-6553F7C3BDD",             # short last group
    ):
        assert _remap_guid(oid, 7) == oid
    assert _remap_guid(None, 7) is None  # missing ids must not crash the remap


def test_remap_guid_is_deterministic_and_tenant_disjoint():
    t1a, t1b, t2 = _remap_guid(GUID, 1), _remap_guid(GUID, 1), _remap_guid(GUID, 2)
    assert t1a == t1b           # replay-identical within a tenant
    assert t1a != GUID          # actually remapped
    assert t1a != t2            # distinct tenants never collide on the same input
    assert _GUID_RE.match(t1a)  # output is itself a well-formed GUID
    assert t1a == t1a.upper()   # canonical uppercase


def test_remap_sid_edge_cases():
    assert _remap_sid("not-a-sid", 3) == "not-a-sid"
    assert _remap_sid("S-1-4-21-1-512", 3) == "S-1-4-21-1-512"      # only S-1-5 shifts
    assert _remap_sid("S-1-5-21-111-512", 0) == "S-1-5-21-111-512"  # tenant 0 = identity
    shifted = _remap_sid("S-1-5-21-111-512", 1)
    assert shifted == "S-1-5-1000000000000021-111-512"  # first subauthority + 10^15
    assert shifted.endswith("-512")                       # RID tail preserved (jewels survive)


def _tiny_base():
    g = NormalizedGraph()
    g.add_node("S-1-5-21-111-512", "Group",
               {"name": "domain admins@CORP.LOCAL", "domain": "CORP.LOCAL"})
    g.add_node("S-1-5-21-111-1101", "User", {"name": "alice"})
    g.add_node(GUID, "CertTemplate", {"name": "UserTemplate"})
    g.add_node("odd-id", "Container", {"name": "plain"})
    g.add_edge("S-1-5-21-111-1101", "S-1-5-21-111-512", "MEMBER_OF")
    return g


def test_make_tenant_on_synthetic_base():
    base = _tiny_base()
    t = make_tenant(base, 1)
    # SIDs shift, GUIDs remap, foreign ids get the ~tNNN fallback
    assert "S-1-5-1000000000000021-111-512" in t.nodes
    assert "odd-id~t001" in t.nodes
    assert not (set(base.nodes) & set(t.nodes)), "tenant must share zero identities with base"
    # edges survive with remapped endpoints and identical rels
    edge = next(iter(t.edges.values()))
    assert edge["rel"] == "MEMBER_OF"
    assert edge["src"] == "S-1-5-1000000000000021-111-1101"
    assert edge["dst"] == "S-1-5-1000000000000021-111-512"
    assert t.stats == {"tenant": 1, "node_count": 4, "edge_count": 1}
    # replay-deterministic on a synthetic base
    t2 = make_tenant(base, 1)
    assert list(t2.nodes) == list(t.nodes)
    assert t2.edges.keys() == t.edges.keys()


def test_tenant_name_remap_handles_email_style_names():
    t = make_tenant(_tiny_base(), 1)
    da = t.nodes["S-1-5-1000000000000021-111-512"]["props"]
    assert da["name"].startswith("domain admins@")   # local part preserved
    assert "T001" in da["name"]                      # tenant marker present
    assert da["name"] != "domain admins@CORP.LOCAL"  # domain part replaced
    assert "T001" in da["domain"] and da["domain"] != "CORP.LOCAL"
    assert t.nodes["S-1-5-1000000000000021-111-1101"]["props"]["name"] == "alice.T001"
    assert t.nodes["odd-id~t001"]["props"]["name"] == "plain.T001"


def test_tenant_name_remap_splits_on_the_last_at_sign_only():
    base = NormalizedGraph()
    base.add_node("S-1-5-21-111-1103", "User", {"name": "svc@sub.dom@corp.example"})
    t = make_tenant(base, 2)
    name = t.nodes["S-1-5-2000000000000021-111-1103"]["props"]["name"]  # 21 + 2*10^15
    assert name.startswith("svc@sub.dom@")  # earlier @ stay in the local part
    assert "T002" in name


def test_tenant_nodes_without_names_are_left_alone():
    base = NormalizedGraph()
    base.add_node("S-1-5-21-111-1104", "User", {})  # no name prop at all
    t = make_tenant(base, 1)
    assert "name" not in t.nodes["S-1-5-1000000000000021-111-1104"]["props"]
