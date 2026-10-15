"""Entra overlay — parser fidelity, hostile-input hardening (DB-free, runs
anywhere), and cross-world reachability on a tiny hybrid estate on the REAL
engine.

Sample-fidelity tests are gated per-test on the AzureHound example file;
the adversarial tests below only need synthetic JSON, so CI gets full Entra
parser coverage without the 62MB download.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tests.conftest import drop_graph
from sever.etl.ad_collectors import NormalizedGraph, parse_ad_dir
from sever.etl.entra_collectors import merge_entra, parse_entra_file

_REPO_ROOT = Path(__file__).resolve().parents[1]
AD_DIR = os.environ.get(
    "SEVER_SAMPLE_DIR", str(_REPO_ROOT / "data" / "ad_sample"))
ENTRA_FILE = os.environ.get(
    "SEVER_ENTRA_FILE",
    str(_REPO_ROOT / "data" / "entra_sample" / "azurehound_example.json"),
)
_SAMPLES_PRESENT = Path(AD_DIR).is_dir() and Path(ENTRA_FILE).is_file()
requires_entrada = pytest.mark.skipif(
    not _SAMPLES_PRESENT,
    reason="sample data not present",
)


# ---- sample fidelity (each test skips when the sample is absent) ----


@requires_entrada
def test_entra_parse_counts():
    az = parse_entra_file(ENTRA_FILE)
    assert az.stats["records"] == 29800
    assert len(az.nodes) > 12000
    assert len(az.edges) > 12000
    labels = {n["label"] for n in az.nodes.values()}
    assert {"AZUser", "AZServicePrincipal", "AZApp", "AZTenant"} <= labels


@requires_entrada
def test_entra_ga_holder_present():
    az = parse_entra_file(ENTRA_FILE)
    ga = [n for n in az.nodes.values()
          if n["label"] == "AZUser" and n["props"].get("name", "").endswith("-GlobalAdministrator")]
    assert len(ga) == 1


@requires_entrada
def test_merged_graph_bridges():
    ad = parse_ad_dir(AD_DIR)
    base_nodes = len(ad.nodes)
    az = parse_entra_file(ENTRA_FILE)
    merged = merge_entra(ad, az)
    assert merged.stats["entra_bridges"] == 9
    assert len(merged.nodes) > base_nodes + 1000
    synced = [e for e in merged.edges.values() if e["rel"] == "SYNCED_TO"]
    assert len(synced) == 2 * 9  # bidirectional: one identity, two worlds


@requires_entrada
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


@requires_entrada
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


@requires_entrada
def test_entra_app_owner_edges_target_app_object_ids():
    az = parse_entra_file(ENTRA_FILE)
    app_ids = {n for n, nd in az.nodes.items() if nd["label"] == "AZApp"}
    owns = [e for e in az.edges.values() if e["props"].get("source_kind") == "AZAppOwner"]
    assert owns, "no AZAppOwner edges"
    assert all(e["dst"] in app_ids for e in owns)


@requires_entrada
def test_entra_arm_role_principals_resolved_not_roleassignment_paths():
    """Every ARM role edge src must be a principal object id, never a
    "/providers/Microsoft.Authorization/roleAssignments/..." path."""
    az = parse_entra_file(ENTRA_FILE)
    bad = [
        e for e in az.edges.values()
        if "roleAssignments/" in e["src"] or "roleAssignments/" in e["dst"]
    ]
    assert bad == []


@requires_entrada
def test_entra_unresolved_nodes_are_flagged():
    """Referenced-but-uncollected principals (AzureHound inlines the object
    in owners/members entries) are materialized honestly with the unresolved
    flag — same contract as the AD parser."""
    az = parse_entra_file(ENTRA_FILE)
    unres = [n for n in az.nodes.values() if n["props"].get("unresolved")]
    assert len(unres) > 100
    assert all(n["label"].startswith("AZ") for n in unres)


@requires_entrada
def test_entra_onprem_group_sids_do_not_match_ad_groups():
    """audit3 finding, pinned: 17 AZGroups carry onPremisesSecurityIdentifier
    (e.g. 28570af0-f6c0-42de-951c-601475afe66b -> S-1-5-21-189290026-...-1110)
    but all from a domain the AD sample never collected — so the AZUser-only
    bridge rule loses nothing on this dataset (9/9 user matches bridge).
    If a future sample syncs groups, extend merge_entra deliberately."""
    az = parse_entra_file(ENTRA_FILE)
    ad = parse_ad_dir(AD_DIR)
    az_group_sids = {n["props"]["onprem_sid"] for n in az.nodes.values()
                     if n["label"] == "AZGroup" and n["props"].get("onprem_sid")}
    ad_group_ids = {oid for oid, nd in ad.nodes.items() if nd["label"] == "Group"}
    ad_user_ids = {oid for oid, nd in ad.nodes.items() if nd["label"] == "User"}
    assert len(az_group_sids) == 17
    assert az_group_sids & ad_group_ids == set()
    az_user_sids = {n["props"]["onprem_sid"] for n in az.nodes.values()
                    if n["label"] == "AZUser" and n["props"].get("onprem_sid")}
    assert len(az_user_sids & ad_user_ids) == 9  # the 9 bridges, nothing missed


@requires_entrada
def test_entra_parse_is_deterministic_edge_set_hash():
    import hashlib

    def edge_hash(g):
        payload = sorted(
            (e["src"], e["dst"], e["rel"], json.dumps(e["props"], sort_keys=True, default=str))
            for e in g.edges.values()
        )
        return hashlib.sha256(json.dumps(payload).encode()).hexdigest()

    graphs = [parse_entra_file(ENTRA_FILE) for _ in range(3)]
    assert len({edge_hash(g) for g in graphs}) == 1  # 3x re-parse, identical edge set
    assert len({json.dumps(g.stats["kind_counts"], sort_keys=True) for g in graphs}) == 1
    assert len({json.dumps(g.stats["skipped"], sort_keys=True) for g in graphs}) == 1


@requires_entrada
def test_merged_stats_are_honest():
    """merge_entra recomputes label/rel censuses for the MERGED graph (the
    pre-merge AD stats are stale) and carries the Entra skip ledger."""
    ad = parse_ad_dir(AD_DIR)
    az = parse_entra_file(ENTRA_FILE)
    merged = merge_entra(ad, az)
    assert merged.stats["node_count"] == len(merged.nodes)
    assert merged.stats["edge_count"] == len(merged.edges)
    assert sum(merged.stats["label_counts"].values()) == len(merged.nodes)
    assert sum(merged.stats["rel_counts"].values()) == len(merged.edges)
    label_c: dict[str, int] = {}
    for n in merged.nodes.values():
        label_c[n["label"]] = label_c.get(n["label"], 0) + 1
    assert merged.stats["label_counts"] == label_c
    assert "AZUser" in merged.stats["label_counts"]
    assert "SYNCED_TO" in merged.stats["rel_counts"]
    assert merged.stats["entra_skipped"] == az.stats["skipped"]


@requires_entrada
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


# ---- adversarial/hostile Entra inputs (DB-free, no sample needed) ----
#
# Same contract as the AD parser: corrupt documents fail LOUD with a clear
# ValueError; wrong-typed records/fields are counted in stats["skipped"] and
# skipped — never a crash, never a garbage edge, never a garbage node id.


def _entra_file(path, doc):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def _assert_entra_invariants(g):
    ids = set(g.nodes)
    dangling = [e for e in g.edges.values() if e["src"] not in ids or e["dst"] not in ids]
    assert dangling == [], f"{len(dangling)} dangling edges: {dangling[:3]}"
    for n in g.nodes.values():
        for k, v in n["props"].items():
            assert not isinstance(v, (dict, list)), f"non-primitive prop {k} on {n['objectid']}"


def test_entra_hostile_doc_not_object_fails_loud(tmp_path):
    f = _entra_file(tmp_path / "az.json", ["not", "an", "object"])
    with pytest.raises(ValueError, match="top level must be a JSON object"):
        parse_entra_file(f)


def test_entra_hostile_data_not_list_fails_loud(tmp_path):
    for bad in ({"data": {"kind": "x"}}, {"data": "string"}, {"data": 7}, {"data": True}):
        f = _entra_file(tmp_path / "az.json", bad)
        with pytest.raises(ValueError, match="'data' must be a list"):
            parse_entra_file(f)


def test_entra_hostile_data_null_and_empty_parse_clean(tmp_path):
    for doc in ({"data": None}, {}):
        f = _entra_file(tmp_path / "az.json", doc)
        g = parse_entra_file(f)
        assert g.stats["records"] == 0
        assert g.nodes == {} and g.edges == {}
        assert g.stats["skipped"] == {}
        _assert_entra_invariants(g)


def test_entra_hostile_non_dict_records_counted(tmp_path):
    f = _entra_file(tmp_path / "az.json", {"data": [
        "a bare string", 42, None,
        {"kind": "AZUser", "data": {"id": "u1", "displayName": "User One"}},
    ]})
    g = parse_entra_file(f)
    assert set(g.nodes) == {"u1"}
    assert g.stats["skipped"] == {"malformed_record": 3}
    assert g.stats["kind_counts"] == {"AZUser": 1, "<malformed>": 3}
    _assert_entra_invariants(g)


def test_entra_hostile_non_string_kind_counted(tmp_path):
    f = _entra_file(tmp_path / "az.json", {"data": [
        {"kind": ["AZUser"], "data": {"id": "x"}},
        {"kind": 42, "data": {"id": "y"}},
    ]})
    g = parse_entra_file(f)
    assert g.nodes == {} and g.edges == {}
    assert g.stats["skipped"] == {"malformed_kind": 2}


def test_entra_hostile_kind_data_not_dict_counted(tmp_path):
    """Previously CRASHED: rec["data"] a string -> data.get AttributeError."""
    f = _entra_file(tmp_path / "az.json", {"data": [
        {"kind": "AZUser", "data": "not-a-dict"},
        {"kind": "AZGroupOwner", "data": ["also", "not"]},
        {"kind": "AZUser", "data": None},  # missing data is fine -> no props
    ]})
    g = parse_entra_file(f)
    assert g.stats["skipped"] == {"malformed_data:AZUser": 1,
                                  "malformed_data:AZGroupOwner": 1,
                                  "missing_id:AZUser": 1}  # the None-data record has no id either
    assert g.nodes == {} and g.edges == {}
    _assert_entra_invariants(g)


def test_entra_hostile_description_wrong_type_never_crashes(tmp_path):
    """Previously CRASHED: (description or "")[:200] on a dict/list raises
    TypeError. Any description value now parses to a <=200-char string."""
    f = _entra_file(tmp_path / "az.json", {"data": [
        {"kind": "AZUser", "data": {"id": "u1", "description": {"long": ["dict"]}}},
        {"kind": "AZUser", "data": {"id": "u2", "description": ["l", "i", "s", "t"]}},
        {"kind": "AZUser", "data": {"id": "u3", "description": "a plain one"}},
    ]})
    g = parse_entra_file(f)
    for oid in ("u1", "u2", "u3"):
        desc = g.nodes[oid]["props"]["description"]
        assert isinstance(desc, str) and 0 < len(desc) <= 200
    _assert_entra_invariants(g)


def test_entra_hostile_ids_wrong_type_no_garbage_node(tmp_path):
    """A dict/int where an id belongs must never become a str(dict) node key
    (previously: node id "{'x': 1}")."""
    f = _entra_file(tmp_path / "az.json", {"data": [
        {"kind": "AZUser", "data": {"id": {"x": 1}, "displayName": "n"}},
        {"kind": "AZUser", "data": {"id": True, "displayName": "b"}},
        {"kind": "AZUser", "data": {"id": "", "displayName": "e"}},
        {"kind": "AZUser", "data": {"id": "real", "displayName": "ok"}},
    ]})
    g = parse_entra_file(f)
    assert set(g.nodes) == {"real"}
    assert g.stats["skipped"] == {"missing_id:AZUser": 3}
    _assert_entra_invariants(g)


def test_entra_hostile_owners_string_not_list_no_garbage_edge(tmp_path):
    """Previously EMITTED A GARBAGE EDGE: owners: "whatever" fell into the
    flat-src branch and became AZOwns "whatever" -> group. A dict value there
    is equally malformed."""
    f = _entra_file(tmp_path / "az.json", {"data": [
        {"kind": "AZGroup", "data": {"id": "grp", "displayName": "G"}},
        {"kind": "AZGroupOwner", "data": {"groupId": "grp", "owners": "whatever"}},
        {"kind": "AZGroupOwner", "data": {"groupId": "grp", "owners": {"owner": {"id": "u1"}}}},
    ]})
    g = parse_entra_file(f)
    assert g.edges == {}, "garbage AZOwns edge emitted from a string owners field"
    assert g.stats["skipped"] == {"edge_malformed_src:AZGroupOwner": 2}
    _assert_entra_invariants(g)


def test_entra_hostile_flat_principal_dict_no_garbage_src(tmp_path):
    """AZAppRoleAssignment's principalId must be a string; a dict there
    previously became str(dict) as the edge src."""
    f = _entra_file(tmp_path / "az.json", {"data": [
        {"kind": "AZServicePrincipal", "data": {"id": "sp1", "displayName": "SP"}},
        {"kind": "AZAppRoleAssignment", "data": {
            "principalId": {"id": "fake"}, "resourceId": "sp1",
            "principalType": "serviceprincipal"}},
    ]})
    g = parse_entra_file(f)
    assert g.edges == {}
    assert g.stats["skipped"] == {"edge_missing_src:AZAppRoleAssignment": 1}
    _assert_entra_invariants(g)


def test_entra_hostile_dst_wrong_type_counted(tmp_path):
    f = _entra_file(tmp_path / "az.json", {"data": [
        {"kind": "AZVM", "data": {"id": "vm1", "displayName": "VM"}},
        {"kind": "AZVMOwner", "data": {"virtualMachineId": {"arm": ["path"]},
                                       "owners": [{"owner": {"id": "u1"}}]}},
        {"kind": "AZVMOwner", "data": {"virtualMachineId": "", "owners": []}},
    ]})
    g = parse_entra_file(f)
    assert g.edges == {}
    assert g.stats["skipped"] == {"edge_missing_dst:AZVMOwner": 2}


def test_entra_hostile_entry_shapes_never_crash_or_invent(tmp_path):
    """owner entries of every wrong shape are skipped; only dict-inlined
    Graph objects materialize unresolved nodes with an honest @odata.type."""
    f = _entra_file(tmp_path / "az.json", {"data": [
        {"kind": "AZGroup", "data": {"id": "grp", "displayName": "G"}},
        {"kind": "AZGroupOwner", "data": {"groupId": "grp", "owners": [
            "a bare string",
            42,
            {"owner": "string-not-dict"},
            {"owner": {"id": {"nested": True}}},
            {"owner": {"id": "ghost-user", "@odata.type": "#microsoft.graph.user",
                       "displayName": "Ghost User"}},
            {"owner": {"properties": {"principalId": "arm-user"}}},
        ]}},
    ]})
    g = parse_entra_file(f)
    owns = [e for e in g.edges.values() if e["rel"] == "AZOwns"]
    assert {(e["src"], e["dst"]) for e in owns} == {("ghost-user", "grp"), ("arm-user", "grp")}
    assert g.nodes["ghost-user"]["label"] == "AZUser"
    assert g.nodes["ghost-user"]["props"].get("unresolved") is True
    assert g.nodes["ghost-user"]["props"].get("name") == "Ghost User"
    # the typeless ARM entry still gets an honest placeholder — never a
    # dangling edge (the sparse-data hole the audit3 invariant test found)
    assert g.nodes["arm-user"]["label"] == "AZPrincipal"
    assert g.nodes["arm-user"]["props"].get("unresolved") is True
    assert g.stats["skipped"] == {"edge_malformed_src:AZGroupOwner": 4}
    _assert_entra_invariants(g)


def test_entra_hostile_unicode_and_duplicate_ids(tmp_path):
    """Unicode display names round-trip verbatim; an id appearing under two
    kinds yields exactly ONE node whose label is deterministic (first kind in
    record order), and reparsing is byte-identical."""
    name = "Ünïcödé クラウド 👾"
    doc = {"data": [
        {"kind": "AZUser", "data": {"id": "dup-1", "displayName": name}},
        {"kind": "AZGroup", "data": {"id": "dup-1", "displayName": "group-with-same-id"}},
        {"kind": "AZGroup", "data": {"id": "grp", "displayName": "G"}},
        {"kind": "AZGroupMember", "data": {
            "groupId": "grp",
            "members": [{"member": {"id": "dup-1", "@odata.type": "#microsoft.graph.user"}}]},
        },
    ]}
    f = _entra_file(tmp_path / "az.json", doc)
    g1, g2 = parse_entra_file(f), parse_entra_file(f)
    assert set(g1.nodes) == {"dup-1", "grp"}
    assert g1.nodes["dup-1"]["label"] == "AZUser"  # first kind wins, deterministically
    assert g1.nodes["dup-1"]["props"]["name"] == name  # unicode survives verbatim
    mo = [e for e in g1.edges.values() if e["rel"] == "AZMemberOf"]
    assert {(e["src"], e["dst"]) for e in mo} == {("dup-1", "grp")}

    def edge_hash(g):
        payload = sorted(
            (e["src"], e["dst"], e["rel"], json.dumps(e["props"], sort_keys=True, default=str))
            for e in g.edges.values()
        )
        import hashlib
        return hashlib.sha256(json.dumps(payload).encode()).hexdigest()

    assert edge_hash(g1) == edge_hash(g2)
    _assert_entra_invariants(g1)


def test_entra_hostile_self_owner_never_emits_self_loop(tmp_path):
    f = _entra_file(tmp_path / "az.json", {"data": [
        {"kind": "AZGroup", "data": {"id": "grp", "displayName": "G"}},
        {"kind": "AZGroupOwner", "data": {"groupId": "grp",
                                         "owners": [{"owner": {"id": "grp"}}]}},
    ]})
    g = parse_entra_file(f)
    assert g.edges == {}
    assert set(g.nodes) == {"grp"}
    _assert_entra_invariants(g)


def test_entra_hostile_one_megabyte_description_truncated_to_cap(tmp_path):
    """The description cap (200 chars) is deliberate and documented; a 1MB
    displayName is NOT truncated (that would be silent corruption)."""
    big_desc, big_name = "D" * (1024 * 1024), "N" * (1024 * 1024)
    f = _entra_file(tmp_path / "az.json", {"data": [
        {"kind": "AZUser", "data": {"id": "u1", "description": big_desc,
                                    "displayName": big_name}},
    ]})
    g = parse_entra_file(f)
    assert len(g.nodes["u1"]["props"]["description"]) == 200
    assert g.nodes["u1"]["props"]["name"] == big_name
    _assert_entra_invariants(g)


def test_entra_hostile_deeply_nested_data_parses(tmp_path):
    deep = {"x": 1}
    for _ in range(200):
        deep = {"n": deep}
    f = _entra_file(tmp_path / "az.json", {"data": [
        {"kind": "AZUser", "data": {"id": "u1", "displayName": "u",
                                    "junk": deep, "description": deep}},
    ]})
    g = parse_entra_file(f)
    assert set(g.nodes) == {"u1"}
    assert len(g.nodes["u1"]["props"]["description"]) == 200
    assert "junk" not in g.nodes["u1"]["props"]  # unknown fields never stored
    _assert_entra_invariants(g)


def test_entra_hostile_unknown_kind_visible_not_parsed(tmp_path):
    """Kinds the model does not consume (the official sample ships 12, e.g.
    AZRoleAssignment, AZKeyVaultAccessPolicy, AZAutomationAccountRoleAssignment)
    stay visible in kind_counts and yield nothing — data, not errors."""
    f = _entra_file(tmp_path / "az.json", {"data": [
        {"kind": "AZRoleAssignment", "data": {"roleAssignments": None}},
        {"kind": "AZKeyVaultAccessPolicy", "data": {"objectId": "x",
                                                    "permissions": {"keys": ["Get"]}}},
        {"kind": "AZWeirdFutureKind", "data": {"id": "whatever"}},
        {"kind": "AZUser", "data": {"id": "u1", "displayName": "u"}},
    ]})
    g = parse_entra_file(f)
    assert set(g.nodes) == {"u1"}
    assert g.edges == {}
    assert g.stats["kind_counts"]["AZRoleAssignment"] == 1
    assert g.stats["kind_counts"]["AZWeirdFutureKind"] == 1
    assert g.stats["skipped"] == {}
    _assert_entra_invariants(g)


def test_entra_hostile_missing_every_optional_field_parses(tmp_path):
    f = _entra_file(tmp_path / "az.json", {"data": [
        {"kind": "AZUser", "data": {"id": "u-bare"}},
        {"kind": "AZUser", "data": {}},  # no id
        {"kind": "AZGroupOwner", "data": {}},  # no dst, no owners
    ]})
    g = parse_entra_file(f)
    assert set(g.nodes) == {"u-bare"}
    assert g.nodes["u-bare"]["props"] == {"owned": False}
    assert g.stats["skipped"] == {"missing_id:AZUser": 1,
                                  "edge_missing_dst:AZGroupOwner": 1}
    _assert_entra_invariants(g)


def test_entra_bridge_requires_exact_ad_user_match(tmp_path):
    """The SYNCED_TO bridge is exact: an AZUser onprem_sid equal to an AD
    User objectid bridges (both directions); anything else never bridges."""
    ad = NormalizedGraph()
    ad.add_node("S-1-5-21-ad-1001", "User", {"name": "andy", "owned": False})
    ad.add_node("S-1-5-21-ad-2002", "Group", {"name": "grp", "owned": False})

    az = NormalizedGraph()
    az.add_node("az-andy", "AZUser", {"name": "andy@cloud", "onprem_sid": "S-1-5-21-ad-1001",
                                      "owned": False})
    az.add_node("az-ghost", "AZUser", {"name": "ghost", "onprem_sid": "S-1-5-21-ad-2002",
                                      "owned": False})  # matches a GROUP, not a user
    az.add_node("az-nosid", "AZUser", {"name": "nosid", "owned": False})
    az.add_node("az-group", "AZGroup", {"name": "g", "onprem_sid": "S-1-5-21-ad-1001",
                                        "owned": False})  # AZGroup never bridges

    merged = merge_entra(ad, az)
    assert merged.stats["entra_bridges"] == 1
    synced = {(e["src"], e["dst"], json.dumps(e["props"], sort_keys=True))
              for e in merged.edges.values() if e["rel"] == "SYNCED_TO"}
    assert synced == {
        ("S-1-5-21-ad-1001", "az-andy", '{"hybrid": true}'),
        ("az-andy", "S-1-5-21-ad-1001", '{"direction": "reverse", "hybrid": true}'),
    }
    # merge is non-mutating: the inputs are untouched
    assert set(ad.nodes) == {"S-1-5-21-ad-1001", "S-1-5-21-ad-2002"}
    assert set(az.nodes) == {"az-andy", "az-ghost", "az-nosid", "az-group"}
    assert len(az.edges) == 0
    _assert_entra_invariants(merged)


def test_entra_merge_invariant_and_stats_on_hostile_graphs(tmp_path):
    """Merging a hostile Entra graph into an AD graph: the unresolved-principal
    invariant holds on the MERGED graph and the recomputed stats are honest."""
    f = _entra_file(tmp_path / "az.json", {"data": [
        {"kind": "AZUser", "data": {"id": "az-andy",
                                    "onPremisesSecurityIdentifier": "S-1-5-21-x-1001"}},
        {"kind": "AZGroup", "data": {"id": "grp"}},
        {"kind": "AZGroupOwner", "data": {"groupId": "grp", "owners": [
            {"owner": {"id": "S-1-5-21-x-1001", "@odata.type": "#microsoft.graph.user"}}]}},
    ]})
    az = parse_entra_file(f)
    ad_dir = tmp_path / "ad"
    ad_dir.mkdir()
    (ad_dir / "20240101000000_users.json").write_text(json.dumps(
        {"data": [{"ObjectIdentifier": "S-1-5-21-x-1001", "Properties": {"name": "andy"}}]}),
        encoding="utf-8")
    ad = parse_ad_dir(ad_dir)
    merged = merge_entra(ad, az)
    _assert_entra_invariants(merged)
    assert merged.stats["entra_bridges"] == 1
    assert merged.stats["rel_counts"].get("SYNCED_TO") == 2
    assert merged.stats["entra_skipped"] == az.stats["skipped"]
